//! npm registry author lookup for a username selector. Keyless -- the official public registry
//! search API (`GET https://registry.npmjs.org/-/v1/search?text=maintainer:{handle}`).
//!
//! One handle resolves to the packages it maintains. The confirmed-on-npm handle rides out as a
//! [`EntityKind::Username`] (package coverage as evidence, not a confidence premium), and each
//! package seeds the rest of the engine:
//!
//! - a maintainer/publisher/author **email** or profile **URL** is kept **only** from a person
//!   record whose own username is the subject, so a co-maintainer's address is never mis-attributed
//!   to the person being scanned -- npm's free-text `author` block routinely names someone else
//!   (a fork's original author, an ex-employee, a company alias);
//! - every **other** npm username on a record is its own [`EntityKind::Username`] lead
//!   (tagged `co-{role}`), so a co-maintainer is surfaced rather than silently dropped;
//! - each package's homepage/repository is a [`EntityKind::Url`], and its host a
//!   [`EntityKind::Domain`] pivot (code forges excluded as noise).
//!
//! Why it earns a place in the keyless set: it both confirms a handle on a code-registry platform
//! (the `code` provider family, independent of social/forums for cross-service correlation) AND
//! frequently exposes the maintainer's operator-published EMAIL -- a high-value handle->identity
//! link npm requires for publishing. A published contact is a lead to review, not proof of who
//! operates the account today.

use std::collections::HashSet;

use serde::Deserialize;

use crate::canonical::{canonical_email, canonical_url};
use crate::domains::host_only;
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid, push_entity};
use crate::error::Error;
use crate::fetch::{FetchOptions, Fetched, answer, decode_json, fetch, whole_response};
use crate::http::{DEFAULT_USER_AGENT, Request, Transport, percent_encode_unreserved};
use crate::source_outcome::SourceExecutionOutcome;

pub const SRC: &str = "npm_author";
const PUBLIC_BASE: &str = "https://registry.npmjs.org";

/// npm's `/-/v1/search` caps `size` at 250. Every package the one page returns is emitted -- these
/// are the subject's own packages, a result not a preview -- so this bounds only the single fetch.
/// An author with more than 250 packages would need cursor pagination (a follow-up).
const MAX_PACKAGES: usize = 250;

/// Confirmed-on-npm handle: a single-source, keyless account-existence lead; package coverage is
/// evidence, not a confidence premium.
const SUBJECT_USERNAME_CONF: f64 = 0.85;
/// An operator-published contact email on the subject's own record.
const EMAIL_CONF: f64 = 0.74;
/// A profile URL on the subject's own record.
const PERSON_URL_CONF: f64 = 0.66;
/// Another npm account that co-maintains one of the subject's packages: a lead, not the subject.
const CO_MAINTAINER_CONF: f64 = 0.70;
/// A package's declared homepage/repository.
const PACKAGE_URL_CONF: f64 = 0.62;
/// The host of a package link, as a pivot.
const DOMAIN_CONF: f64 = 0.60;

/// Code forges whose host is noise as a `Domain` pivot: a package link there is already a `Url`.
const CODE_FORGES: &[&str] = &[
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "npmjs.com",
    "npmjs.org",
];

#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcome: SourceExecutionOutcome,
}

#[derive(Debug, Default, Deserialize)]
struct SearchResp {
    #[serde(default)]
    objects: Vec<SearchObject>,
    #[serde(default)]
    total: u64,
}

#[derive(Debug, Deserialize)]
struct SearchObject {
    #[serde(default)]
    package: Option<Package>,
}

#[derive(Debug, Deserialize)]
struct Package {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    links: Option<Links>,
    #[serde(default)]
    author: Option<Person>,
    #[serde(default)]
    publisher: Option<Person>,
    #[serde(default)]
    maintainers: Vec<Person>,
}

#[derive(Debug, Deserialize)]
struct Links {
    #[serde(default)]
    homepage: Option<String>,
    #[serde(default)]
    repository: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Person {
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    url: Option<String>,
}

/// Whether `handle` is a shape npm would key a maintainer on: non-empty, at most 214 bytes (npm's
/// package-name limit, which bounds usernames too), lowercase url-safe letters, digits, `-`, `_`
/// and `.`. The `username` front-end has already canonicalised its selector; this guards a direct
/// or scripted call. **Pure.**
#[must_use]
pub fn valid_handle(handle: &str) -> bool {
    !handle.is_empty()
        && handle.len() <= 214
        && handle
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

/// The `/-/v1/search` URL for the packages `handle` maintains. **Pure.**
#[must_use]
pub fn search_url(handle: &str) -> String {
    format!(
        "{PUBLIC_BASE}/-/v1/search?text=maintainer:{}&size={MAX_PACKAGES}",
        percent_encode_unreserved(handle)
    )
}

/// The public profile page a human reads for a handle. **Pure.**
fn profile_url(handle: &str) -> String {
    format!("https://www.npmjs.com/~{handle}")
}

/// Query the packages one npm handle maintains, keyless.
///
/// # Errors
/// Returns a network-boundary error when the guarded fetch refuses a URL.
pub fn lookup<T: Transport + ?Sized>(
    transport: &T,
    username: &str,
    scan_id: &str,
    now_unix: u64,
) -> Result<Report, Error> {
    let handle = username.trim().trim_start_matches('@').to_ascii_lowercase();
    if !valid_handle(&handle) {
        return Ok(miss(SourceExecutionOutcome::inconclusive(
            SRC,
            now_unix,
            "selector is not a valid npm handle",
        )));
    }
    let fetched = fetch(
        transport,
        Request::get(search_url(&handle))
            .header("accept", "application/json")
            .header("user-agent", DEFAULT_USER_AGENT),
        None,
        &FetchOptions::no_redirects().paced(),
        SRC,
        now_unix,
    )?;
    Ok(interpret(&fetched, &handle, scan_id, now_unix).unwrap_or_else(miss))
}

/// A report that found nothing, carrying only its outcome. **Pure.**
fn miss(outcome: SourceExecutionOutcome) -> Report {
    Report {
        entities: Vec::new(),
        outcome,
    }
}

/// Turn one fetched search response into a report; `Err` is the outcome of a response that named no
/// packages. A search that ran and matched nothing is a clean negative, not a failure. **Pure.**
fn interpret(
    fetched: &Fetched,
    handle: &str,
    scan_id: &str,
    now_unix: u64,
) -> Result<Report, SourceExecutionOutcome> {
    let response = whole_response(fetched, "npm registry")?;
    answer(fetched, "npm registry")?;
    let resp: SearchResp = decode_json(response, SRC, now_unix, "npm registry")?;
    if resp.objects.is_empty() {
        return Err(
            SourceExecutionOutcome::valid_zero(SRC, now_unix).with_http_status(response.status)
        );
    }
    let mut entities = build_entities(&resp, handle, scan_id);
    merge_by_uid(&mut entities);
    Ok(Report {
        outcome: SourceExecutionOutcome::success(SRC, now_unix, entities.len())
            .with_http_status(response.status),
        entities,
    })
}

/// De-duplication sets shared across one search's packages, so each distinct email, URL, domain
/// and co-maintainer is emitted once.
#[derive(Default)]
struct Seen {
    emails: HashSet<String>,
    urls: HashSet<String>,
    domains: HashSet<String>,
    co_maintainers: HashSet<String>,
}

/// Evidence naming the package a value came from, omitting the attribute when the name is blank
/// (dead-field hygiene). **Pure.**
fn package_evidence(scan_id: &str, summary: String, pkg: &str) -> Evidence {
    let base = Evidence::new(EvidenceProvenance::for_scan(SRC, scan_id), summary);
    if pkg.is_empty() {
        base
    } else {
        base.with_attr("package", pkg)
    }
}

/// Map a decoded npm maintainer search to its entities. **Pure** (no network/IO), so the
/// package -> email/url/username mapping is unit-testable off JSON fixtures.
///
/// `handle` is the already-lowercased queried username. The caller has short-circuited an empty
/// `objects` list, so the confirmed-on-npm [`EntityKind::Username`] is always emitted. Contact
/// emails and profile URLs are taken only from records whose own username is the subject (so a
/// co-maintainer's address is not mis-attributed); every other username becomes its own co-
/// maintainer lead; emails, URLs, domains and co-maintainers are de-duplicated and every returned
/// package is surfaced.
fn build_entities(resp: &SearchResp, handle: &str, scan_id: &str) -> Vec<Entity> {
    let mut entities = Vec::new();
    let mut seen = Seen::default();
    let mut package_names: Vec<&str> = Vec::new();

    for object in &resp.objects {
        let Some(package) = object.package.as_ref() else {
            continue;
        };
        let pkg = package.name.as_deref().unwrap_or("").trim();
        if !pkg.is_empty() {
            package_names.push(pkg);
        }
        add_people(package, handle, pkg, scan_id, &mut entities, &mut seen);
        add_package_links(package, pkg, scan_id, &mut entities, &mut seen);
    }

    add_subject(handle, resp.total, &package_names, scan_id, &mut entities);
    entities
}

/// The subject's own published contacts and every co-maintainer lead from one package's person
/// records. npm exposes three genuinely distinct person fields, so the evidence names which one a
/// value came from: `publisher` (the account that ran `npm publish`), `author` (self-declared free
/// text, possibly stale), `maintainer` (the current list). **Pure.**
fn add_people(
    package: &Package,
    handle: &str,
    pkg: &str,
    scan_id: &str,
    entities: &mut Vec<Entity>,
    seen: &mut Seen,
) {
    let people = package
        .publisher
        .iter()
        .map(|person| ("publisher", person))
        .chain(package.author.iter().map(|person| ("author", person)))
        .chain(
            package
                .maintainers
                .iter()
                .map(|person| ("maintainer", person)),
        );
    for (role, person) in people {
        // The queried handle is the ONLY thing tying any of these records to the person being
        // scanned (REQ-NPMAUTHOR-001): a record with no username, or another account's username,
        // is not evidence about the subject, so its email and URL are never emitted as the
        // subject's. Its username is surfaced instead, as a co-maintainer lead.
        let is_subject = person
            .username
            .as_deref()
            .is_some_and(|name| name.eq_ignore_ascii_case(handle));
        if is_subject {
            if let Some(email) = person
                .email
                .as_deref()
                .map(str::trim)
                .map(str::to_ascii_lowercase)
                .filter(|email| canonical_email(email).is_some())
                .filter(|email| seen.emails.insert((*email).clone()))
            {
                push_entity(
                    entities,
                    EntityKind::Email,
                    &email,
                    EMAIL_CONF,
                    scan_id,
                    package_evidence(scan_id, format!("npm {role} email"), pkg),
                    &["npm", "public-contact"],
                );
            }
            if let Some(url) = person
                .url
                .as_deref()
                .map(str::trim)
                .filter(|url| canonical_url(url).is_some())
                .filter(|url| seen.urls.insert((*url).to_owned()))
            {
                push_entity(
                    entities,
                    EntityKind::Url,
                    url,
                    PERSON_URL_CONF,
                    scan_id,
                    package_evidence(scan_id, format!("npm {role} URL"), pkg),
                    &["npm", "public-profile"],
                );
            }
        } else if let Some(name) = person
            .username
            .as_deref()
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(str::to_ascii_lowercase)
            .filter(|name| seen.co_maintainers.insert((*name).clone()))
        {
            push_entity(
                entities,
                EntityKind::Username,
                &name,
                CO_MAINTAINER_CONF,
                scan_id,
                package_evidence(scan_id, format!("npm co-{role}"), pkg),
                &["npm", "code"],
            );
        }
    }
}

/// One package's homepage/repository as a [`EntityKind::Url`], and each non-forge host as a
/// [`EntityKind::Domain`] pivot (a forge host is already the URL, so it would be noise). **Pure.**
fn add_package_links(
    package: &Package,
    pkg: &str,
    scan_id: &str,
    entities: &mut Vec<Entity>,
    seen: &mut Seen,
) {
    let Some(links) = package.links.as_ref() else {
        return;
    };
    for link in [links.homepage.as_deref(), links.repository.as_deref()]
        .into_iter()
        .flatten()
        .map(str::trim)
        .filter(|link| canonical_url(link).is_some())
    {
        if seen.urls.insert(link.to_owned()) {
            push_entity(
                entities,
                EntityKind::Url,
                link,
                PACKAGE_URL_CONF,
                scan_id,
                package_evidence(scan_id, format!("npm package link ({pkg})"), pkg),
                &["npm", "code"],
            );
        }
        let host = host_only(link).to_ascii_lowercase();
        if host.contains('.')
            && !CODE_FORGES.contains(&host.as_str())
            && seen.domains.insert(host.clone())
        {
            push_entity(
                entities,
                EntityKind::Domain,
                &host,
                DOMAIN_CONF,
                scan_id,
                package_evidence(scan_id, format!("npm package link domain ({pkg})"), pkg),
                &["npm", crate::tags::DERIVED],
            );
        }
    }
}

/// The confirmed-on-npm handle, emitted last so its evidence can name a sample of the packages. A
/// single-source account-existence lead; package coverage rides as evidence, not a premium. **Pure.**
fn add_subject(
    handle: &str,
    total: u64,
    package_names: &[&str],
    scan_id: &str,
    entities: &mut Vec<Entity>,
) {
    let sample = package_names
        .iter()
        .take(8)
        .copied()
        .collect::<Vec<_>>()
        .join(", ");
    let mut subject =
        package_evidence(scan_id, format!("npm maintainer of {total} package(s)"), "")
            .with_attr("package_count", total.to_string())
            .with_attr("profile_url", profile_url(handle));
    if !sample.is_empty() {
        subject = subject.with_attr("packages", sample);
    }
    push_entity(
        entities,
        EntityKind::Username,
        handle,
        SUBJECT_USERNAME_CONF,
        scan_id,
        subject,
        &["npm", "code"],
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source_outcome::SourceOutcomeKind;
    use crate::test_support::OneResponse;

    /// A maintainer with: a subject email+url, a co-maintainer with a DIFFERENT email (must NOT be
    /// attributed to the subject), an `author` block naming someone else, a package homepage on a
    /// personal domain and a repository on a code forge.
    const PACKAGES: &str = r#"{
      "total": 2,
      "objects": [
        {"package": {
          "name": "left-pad",
          "links": {"homepage": "https://janedev.example/", "repository": "https://github.com/jane/left-pad"},
          "author": {"username": "someone-else", "email": "ghost@fork.example"},
          "publisher": {"username": "jane", "email": "jane@jane.example", "url": "https://janedev.example/about"},
          "maintainers": [
            {"username": "jane", "email": "jane@jane.example"},
            {"username": "co-dev", "email": "codev@other.example"}
          ]
        }},
        {"package": {
          "name": "right-pad",
          "publisher": {"username": "jane", "email": "jane@jane.example"},
          "maintainers": [{"username": "jane", "email": "jane@jane.example"}]
        }}
      ]
    }"#;

    fn report_of(body: &str, handle: &str) -> Report {
        lookup(&OneResponse::json(200, body), handle, "scan-npm", 1).expect("lookup runs")
    }

    fn has(report: &Report, kind: &EntityKind, value: &str) -> bool {
        report
            .entities
            .iter()
            .any(|entity| entity.kind == *kind && entity.raw_value == value)
    }

    #[test]
    fn valid_handle_accepts_npm_shaped_handles_only() {
        assert!(valid_handle("jane"));
        assert!(valid_handle("jane.doe_2"));
        assert!(!valid_handle(""));
        assert!(!valid_handle("../etc"));
        assert!(!valid_handle("has space"));
        assert!(!valid_handle(&"x".repeat(215)));
    }

    #[test]
    fn the_search_url_carries_the_maintainer_filter_and_size() {
        assert_eq!(
            search_url("jane"),
            "https://registry.npmjs.org/-/v1/search?text=maintainer:jane&size=250"
        );
    }

    #[test]
    fn the_subject_handle_and_its_own_contacts_are_emitted() {
        let report = report_of(PACKAGES, "jane");
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
        assert!(has(&report, &EntityKind::Username, "jane"));
        assert!(has(&report, &EntityKind::Email, "jane@jane.example"));
        assert!(has(
            &report,
            &EntityKind::Url,
            "https://janedev.example/about"
        ));
        // The subject's confirmed username carries package coverage as evidence.
        let subject = report
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Username && e.raw_value == "jane")
            .expect("subject username");
        let ev = &subject.evidence[0];
        assert_eq!(
            ev.attributes.get("package_count").map(String::as_str),
            Some("2")
        );
        assert_eq!(
            ev.attributes.get("profile_url").map(String::as_str),
            Some("https://www.npmjs.com/~jane")
        );
    }

    #[test]
    fn a_co_maintainers_email_is_never_attributed_to_the_subject() {
        // REQ-NPMAUTHOR-001: only records whose username IS the subject contribute a contact.
        let report = report_of(PACKAGES, "jane");
        assert!(
            !has(&report, &EntityKind::Email, "codev@other.example"),
            "co-maintainer email mis-attributed: {:#?}",
            report.entities
        );
        assert!(
            !has(&report, &EntityKind::Email, "ghost@fork.example"),
            "author-block email mis-attributed: {:#?}",
            report.entities
        );
        // The co-maintainer handle itself IS surfaced, as a lead, not dropped.
        assert!(has(&report, &EntityKind::Username, "co-dev"));
        // ...but the other-account author with no bearing is only surfaced as its handle too.
        assert!(has(&report, &EntityKind::Username, "someone-else"));
    }

    #[test]
    fn package_links_become_urls_and_non_forge_hosts_become_domains() {
        let report = report_of(PACKAGES, "jane");
        assert!(has(&report, &EntityKind::Url, "https://janedev.example/"));
        assert!(has(&report, &EntityKind::Domain, "janedev.example"));
        // The code-forge repository is a Url but NOT a Domain pivot (noise).
        assert!(has(
            &report,
            &EntityKind::Url,
            "https://github.com/jane/left-pad"
        ));
        assert!(!has(&report, &EntityKind::Domain, "github.com"));
    }

    #[test]
    fn a_handle_with_no_packages_is_a_clean_negative() {
        let report = report_of(r#"{"objects":[],"total":0}"#, "nobody");
        assert!(report.entities.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::ValidZero);
    }

    #[test]
    fn an_invalid_handle_makes_no_request_and_is_inconclusive() {
        let transport = crate::test_support::ScriptedTransport::new(Vec::new());
        let report = lookup(&transport, "../etc", "scan", 1).expect("runs");
        assert!(
            transport.seen.borrow().is_empty(),
            "no request for a bad handle"
        );
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Inconclusive);
    }

    #[test]
    fn malformed_json_is_parser_drift() {
        let report = report_of("{not json", "jane");
        assert_eq!(report.outcome.kind, SourceOutcomeKind::ParserDrift);
        assert!(report.entities.is_empty());
    }

    #[test]
    fn a_refusal_is_not_read_as_a_zero() {
        let report = report_of("forbidden", "jane");
        assert!(!report.outcome.kind.is_accepted(), "{:?}", report.outcome);
    }
}
