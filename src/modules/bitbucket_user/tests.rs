use super::*;
use crate::core::confidence;

fn make_workspace(
    slug: &str,
    name: Option<&str>,
    is_personal: bool,
    profile_href: Option<&str>,
) -> BbWorkspace {
    BbWorkspace {
        slug: slug.to_string(),
        name: name.map(str::to_string),
        is_personal,
        is_private: false,
        created_on: Some("2018-11-29T02:09:41.662144+00:00".to_string()),
        links: profile_href.map(|href| BbLinks {
            html: Some(BbLink {
                href: Some(href.to_string()),
            }),
        }),
    }
}

fn repo(
    full_name: &str,
    language: &str,
    updated_on: &str,
    website: Option<&str>,
    fork_of: Option<&str>,
) -> BbRepo {
    BbRepo {
        full_name: Some(full_name.to_string()),
        language: Some(language.to_string()),
        updated_on: Some(updated_on.to_string()),
        website: website.map(str::to_string),
        parent: fork_of.map(|upstream| BbRepoParent {
            full_name: Some(upstream.to_string()),
        }),
    }
}

fn no_repositories() -> RepoReading {
    RepoReading::Read(BbRepoPage::default())
}

fn of_kind(ents: &[Entity], kind: EntityKind) -> Option<&Entity> {
    ents.iter().find(|e| e.kind == kind)
}

fn attr<'a>(e: &'a Entity, key: &str) -> Option<&'a str> {
    e.evidence
        .first()
        .expect("every entity carries the workspace evidence")
        .attributes
        .get(key)
        .map(String::as_str)
}

#[test]
fn emits_username_and_profile_url_from_links() {
    let ws = make_workspace("jdev", None, false, Some("https://bitbucket.org/jdev/"));
    let ents = build_entities(ws, no_repositories(), "scan-bb-001");
    let u = of_kind(&ents, EntityKind::Username).expect("Username");
    assert_eq!(u.value, "jdev");
    assert!(u.has_tag("bitbucket") && u.has_tag("public-profile"));
    // OD-19 cohort canon: single-source confirmed-account lookup = 0.85.
    assert!((u.confidence - confidence::HIGH_PLUSPLUS_PLUS).abs() < 0.01);
    // The API's link, trailing slash trimmed.
    let url = of_kind(&ents, EntityKind::Url).expect("Url");
    assert_eq!(url.value, "https://bitbucket.org/jdev");
    assert_eq!(attr(u, "profile_url"), Some("https://bitbucket.org/jdev"));
    assert_eq!(
        attr(u, "created_on"),
        Some("2018-11-29T02:09:41.662144+00:00")
    );
    assert_eq!(attr(u, "is_private"), Some("false"));
}

#[test]
fn falls_back_to_constructed_profile_url_when_links_absent() {
    let ws = make_workspace("jdev", None, false, None);
    let ents = build_entities(ws, no_repositories(), "scan-bb-002");
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Url && e.value == "https://bitbucket.org/jdev")
    );
}

#[test]
fn a_personal_workspaces_multi_word_name_is_the_account_holder() {
    let ws = make_workspace("jdev", Some("Jane Developer"), true, None);
    let ents = build_entities(ws, no_repositories(), "scan-bb-003");
    let p = of_kind(&ents, EntityKind::Person).expect("Person from the display name");
    assert_eq!(p.value, "Jane Developer");
    assert!(p.has_tag("bitbucket") && !p.has_tag("workspace-name"));
    assert!((p.confidence - confidence::HIGH_PLUS).abs() < 0.01);
    assert_eq!(attr(p, "workspace_kind"), Some("personal"));
    assert_eq!(attr(p, "source_field"), Some("name"));
    assert_eq!(attr(p, "workspace_name"), Some("Jane Developer"));
}

/// Bitbucket marks only the personal workspaces created under its 2019
/// workspace model; an account it migrated in 2018 reads `is_personal: false`
/// whether it is a person's or a team's, so its name is a Person one rung
/// lower and says so.
#[test]
fn an_unmarked_workspaces_name_is_one_rung_lower_and_tagged() {
    let ws = make_workspace("zzzeek", Some("Mike Bayer"), false, None);
    let ents = build_entities(ws, no_repositories(), "scan-bb-004");
    let p = of_kind(&ents, EntityKind::Person).expect("Person from the display name");
    assert_eq!(p.value, "Mike Bayer");
    assert!(p.has_tag("bitbucket") && p.has_tag("workspace-name"));
    assert!((p.confidence - confidence::NOTABLE).abs() < 0.01);
    assert_eq!(attr(p, "workspace_kind"), Some("unmarked"));
}

#[test]
fn single_word_name_does_not_emit_person() {
    let ws = make_workspace("torvalds", Some("DoLoop"), false, None);
    let ents = build_entities(ws, no_repositories(), "scan-bb-005");
    assert!(ents.iter().all(|e| e.kind != EntityKind::Person));
    assert_eq!(ents.len(), 2, "the Username and the profile Url only");
}

#[test]
fn empty_slug_returns_no_entities() {
    let ws = make_workspace("", Some("Jane Developer"), true, None);
    assert!(build_entities(ws, no_repositories(), "scan-bb-006").is_empty());
}

/// The listing's reading is evidence on every entity: the public count,
/// the languages, the newest activity, the first repositories, and the
/// workspace's own projects' websites — never a fork's, whose website is the
/// upstream project's.
#[test]
fn the_repository_reading_is_written_into_the_evidence() {
    let ws = make_workspace("zzzeek", Some("Mike Bayer"), false, None);
    let page = RepoReading::Read(BbRepoPage {
        size: Some(35),
        values: vec![
            repo(
                "zzzeek/requests",
                "python",
                "2024-01-01T00:00:00.000000+00:00",
                Some("https://requests.example"),
                Some("psf/requests"),
            ),
            repo(
                "zzzeek/sqlalchemy",
                "python",
                "2023-10-31T02:15:03.767566+00:00",
                Some("http://www.sqlalchemy.org"),
                None,
            ),
            repo(
                "zzzeek/alembic",
                "Python",
                "2023-10-27T20:09:01.454581+00:00",
                Some("http://alembic.sqlalchemy.org/"),
                None,
            ),
            repo(
                "zzzeek/testgerrit",
                "",
                "2023-03-26T01:49:26.344387+00:00",
                Some(""),
                None,
            ),
        ],
    });
    let ents = build_entities(ws, page, "scan-bb-007");
    let u = of_kind(&ents, EntityKind::Username).expect("Username");
    assert_eq!(attr(u, "public_repositories"), Some("35"));
    assert_eq!(attr(u, "languages"), Some("Python, python"));
    assert_eq!(
        attr(u, "last_public_activity"),
        Some("2024-01-01T00:00:00.000000+00:00")
    );
    assert_eq!(
        attr(u, "repositories"),
        Some("zzzeek/requests, zzzeek/sqlalchemy, zzzeek/alembic, zzzeek/testgerrit")
    );
    assert_eq!(
        attr(u, "project_websites"),
        Some("http://www.sqlalchemy.org, http://alembic.sqlalchemy.org/"),
        "a fork's website is the upstream project's, never this workspace's"
    );
    assert_eq!(
        attr(u, "forks"),
        Some("zzzeek/requests (fork of psf/requests)"),
        "a fork names its upstream"
    );
    // The Person carries the same reading.
    let p = of_kind(&ents, EntityKind::Person).expect("Person");
    assert_eq!(attr(p, "public_repositories"), Some("35"));
}

/// A listing that could not be read is said so in the evidence; the
/// workspace's own answer — the confirmed handle and its profile — never
/// depends on it, and the absence is never "no repositories".
#[test]
fn a_listing_that_could_not_be_read_is_said_so_and_the_workspace_still_stands() {
    let ws = make_workspace("jespern", Some("Jesper Noehr"), false, None);
    let why = "bitbucket_user: HTTP 500 Internal Server Error: upstream".to_string();
    let ents = build_entities(ws, RepoReading::NotRead(why), "scan-bb-008");
    let u = of_kind(&ents, EntityKind::Username).expect("Username");
    assert_eq!(u.value, "jespern");
    assert!(of_kind(&ents, EntityKind::Url).is_some());
    assert_eq!(
        attr(u, "public_repositories"),
        Some("not read: bitbucket_user: HTTP 500 Internal Server Error: upstream")
    );
    assert_eq!(attr(u, "languages"), None);
    assert_eq!(attr(u, "repositories"), None);
    assert_eq!(attr(u, "forks"), None);
}

/// The real request path against a loopback answering as Bitbucket does
/// (bodies captured live 2026-09-15): a handle nobody holds is the clean
/// negative; a handle is resolved case-insensitively to its workspace and the
/// public-repository page is read (the partial response the `fields=`
/// selector asks for); a workspace Bitbucket resolves to another slug is not
/// the handle; a listing that fails leaves the workspace standing and says
/// why; a throttle is the typed rate limit, never a module fault.
#[tokio::test]
async fn the_lookup_resolves_the_workspace_and_types_every_other_answer() {
    use crate::core::error::Error;
    use crate::util::http::test_server::{Canned, serve};
    let base = serve(vec![
        // 1. no workspace holds the handle
        Canned::json(
            404,
            r#"{"type": "error", "error": {"message": "No workspace with identifier 'nobody-holds-this'."}}"#,
        ),
        // 2. the workspace, then its public repositories
        Canned::json(200, WORKSPACE_ZZZEEK),
        Canned::json(200, REPOSITORIES_ZZZEEK),
        // 3. an alias: the slug Bitbucket resolved is not the handle
        Canned::json(200, WORKSPACE_ALIAS),
        // 4. the workspace, then a listing that fails
        Canned::json(200, WORKSPACE_ZZZEEK),
        Canned::text(500, "upstream"),
        // 5. a throttle on the workspace itself
        Canned::text(429, "Rate limit for this resource has been exceeded"),
    ])
    .await;
    let client = reqwest::Client::new();
    let ws_base = format!("{base}/2.0/workspaces");
    let repo_base = format!("{base}/2.0/repositories");

    let absent = lookup(&client, &ws_base, &repo_base, "nobody-holds-this")
        .await
        .expect("a 404 is the clean negative, not an error");
    assert!(absent.is_none());

    let (ws, reading) = lookup(&client, &ws_base, &repo_base, "ZZZeek")
        .await
        .expect("a 200 workspace")
        .expect("the handle's workspace");
    assert_eq!(ws.slug, "zzzeek");
    assert_eq!(ws.name.as_deref(), Some("Mike Bayer"));
    assert!(!ws.is_personal);
    assert_eq!(
        ws.created_on.as_deref(),
        Some("2018-11-29T02:09:41.662144+00:00")
    );
    let RepoReading::Read(page) = reading else {
        panic!("the listing was answered and must be read");
    };
    assert_eq!(page.size, Some(35));
    assert_eq!(
        page.values[0].full_name.as_deref(),
        Some("zzzeek/sqlalchemy")
    );
    assert_eq!(page.values[0].language.as_deref(), Some("python"));
    assert_eq!(
        page.values[0].website.as_deref(),
        Some("http://www.sqlalchemy.org")
    );
    assert!(page.values[0].parent.is_none(), "not a fork");
    let ents = build_entities(ws, RepoReading::Read(page), "scan-bb-009");
    assert_eq!(
        ents.iter().map(|e| e.kind.clone()).collect::<Vec<_>>(),
        vec![EntityKind::Username, EntityKind::Url, EntityKind::Person]
    );
    assert_eq!(attr(&ents[0], "public_repositories"), Some("35"));

    let alias = lookup(&client, &ws_base, &repo_base, "zzzeek")
        .await
        .expect("a 200 workspace");
    assert!(
        alias.is_none(),
        "a workspace resolved to another slug is not the handle"
    );

    let (ws, reading) = lookup(&client, &ws_base, &repo_base, "zzzeek")
        .await
        .expect("the workspace answered")
        .expect("the handle's workspace");
    assert_eq!(ws.slug, "zzzeek");
    let RepoReading::NotRead(why) = reading else {
        panic!("a failed listing is NotRead, never an empty page");
    };
    assert!(why.contains("HTTP 500"), "{why}");

    let Err(err) = lookup(&client, &ws_base, &repo_base, "zzzeek").await else {
        panic!("a 429 is an error");
    };
    assert!(matches!(err, Error::RateLimited(_)), "{err}");
}

/// The provider contract this module runs on. `GET /2.0/users/{username}` was
/// removed by Bitbucket's 2019 username deprecation and answers 404 for every
/// handle, so the module read every account as absent (28 of 28 sweeps
/// `empty`); the handle is a workspace. And Bitbucket's partial responses
/// return only the fields named in `fields=`: a field the decoder reads but
/// the selector omits is silently absent on every answer.
#[test]
fn the_lookup_addresses_the_workspace_resources_and_asks_for_every_decoded_field() {
    assert_eq!(WORKSPACES_BASE, "https://api.bitbucket.org/2.0/workspaces");
    assert_eq!(
        REPOSITORIES_BASE,
        "https://api.bitbucket.org/2.0/repositories"
    );
    for base in [WORKSPACES_BASE, REPOSITORIES_BASE] {
        assert!(
            !base.contains("/users"),
            "{base}: the users resource is gone"
        );
    }
    let selected: Vec<&str> = REPO_FIELDS.split(',').collect();
    assert!(selected.contains(&"size"));
    for field in [
        "full_name",
        "language",
        "updated_on",
        "website",
        "parent.full_name",
    ] {
        let want = format!("values.{field}");
        assert!(
            selected.contains(&want.as_str()),
            "{want} is decoded but not requested"
        );
    }
}

/// `GET /2.0/workspaces/zzzeek`, captured live 2026-09-15 (trimmed to the
/// keys the module and a reader need).
const WORKSPACE_ZZZEEK: &str = r#"{"type": "workspace", "uuid": "{773a542b-6c78-44ed-ab1a-c0b170489ece}", "name": "Mike Bayer", "slug": "zzzeek", "is_private": false, "is_privacy_enforced": false, "created_on": "2018-11-29T02:09:41.662144+00:00", "forking_mode": "allow_forks", "is_personal": false, "links": {"avatar": {"href": "https://bitbucket.org/workspaces/zzzeek/avatar/?ts=1543457381"}, "html": {"href": "https://bitbucket.org/zzzeek/"}, "repositories": {"href": "https://api.bitbucket.org/2.0/repositories/zzzeek"}, "self": {"href": "https://api.bitbucket.org/2.0/workspaces/zzzeek"}}}"#;

/// The same answer with the slug Bitbucket would return for an alias.
const WORKSPACE_ALIAS: &str = r#"{"type": "workspace", "uuid": "{773a542b-6c78-44ed-ab1a-c0b170489ece}", "name": "Somebody Else", "slug": "someone-else", "is_private": false, "is_privacy_enforced": false, "created_on": "2018-11-29T02:09:41.662144+00:00", "forking_mode": "allow_forks", "is_personal": false, "links": {"avatar": {"href": "https://bitbucket.org/workspaces/zzzeek/avatar/?ts=1543457381"}, "html": {"href": "https://bitbucket.org/zzzeek/"}, "repositories": {"href": "https://api.bitbucket.org/2.0/repositories/zzzeek"}, "self": {"href": "https://api.bitbucket.org/2.0/workspaces/zzzeek"}}}"#;

/// `GET /2.0/repositories/zzzeek?pagelen=4&sort=-updated_on&fields=…`,
/// captured live 2026-09-15 — the partial response the selector asks for.
const REPOSITORIES_ZZZEEK: &str = r#"{"values": [{"full_name": "zzzeek/sqlalchemy", "website": "http://www.sqlalchemy.org", "updated_on": "2023-10-31T02:15:03.767566+00:00", "language": "python", "parent": null}, {"full_name": "zzzeek/alembic", "website": "http://alembic.sqlalchemy.org/", "updated_on": "2023-10-27T20:09:01.454581+00:00", "language": "python", "parent": null}, {"full_name": "zzzeek/dogpile.cache", "website": "https://dogpilecache.sqlalchemy.org", "updated_on": "2023-10-12T20:56:50.718048+00:00", "language": "python", "parent": null}, {"full_name": "zzzeek/mako", "website": "http://www.makotemplates.org/", "updated_on": "2023-09-18T20:31:15.339533+00:00", "language": "python", "parent": null}], "size": 35}"#;
