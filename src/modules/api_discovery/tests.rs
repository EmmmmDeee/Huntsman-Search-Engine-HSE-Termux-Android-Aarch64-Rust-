use super::*;

// ── Fixtures: real shapes, captured live 2026-09-22 ─────────────────────────

/// GitLab's OIDC/OAuth metadata (served identically at both well-knowns): the
/// issuer and every endpoint on the queried host itself.
const GITLAB_META: &str = r#"{
  "issuer": "https://gitlab.com",
  "authorization_endpoint": "https://gitlab.com/oauth/authorize",
  "token_endpoint": "https://gitlab.com/oauth/token",
  "revocation_endpoint": "https://gitlab.com/oauth/revoke",
  "introspection_endpoint": "https://gitlab.com/oauth/introspect",
  "userinfo_endpoint": "https://gitlab.com/oauth/userinfo",
  "jwks_uri": "https://gitlab.com/oauth/discovery/keys",
  "scopes_supported": ["api", "read_api", "openid", "profile", "email"],
  "grant_types_supported": ["authorization_code", "refresh_token"]
}"#;

/// Google's OIDC metadata: the endpoints live on SIBLING hosts — the
/// owner-declared infrastructure pivots.
const GOOGLE_META: &str = r#"{
  "issuer": "https://accounts.google.com",
  "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
  "device_authorization_endpoint": "https://oauth2.googleapis.com/device/code",
  "token_endpoint": "https://oauth2.googleapis.com/token",
  "userinfo_endpoint": "https://openidconnect.googleapis.com/v1/userinfo",
  "revocation_endpoint": "https://oauth2.googleapis.com/revoke",
  "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
  "scopes_supported": ["openid", "email", "profile"]
}"#;

/// Atlassian's MCP server (RFC 9728): `resource` with a trailing slash, and an
/// authorization server on a sibling host WITH a path.
const ATLASSIAN_PRM: &str = r#"{
  "resource": "https://mcp.atlassian.com/",
  "authorization_servers": ["https://auth.atlassian.com/VCeDsk8ZHncYF1g234fKtc4lNipbBhu3"],
  "bearer_methods_supported": ["header"],
  "scopes_supported": ["read:me", "read:jira-work", "write:jira-work"]
}"#;

/// Asana's MCP server (RFC 9728): self-hosted authorization server, a
/// `resource_name` and `resource_documentation`.
const ASANA_PRM: &str = r#"{
  "resource": "https://mcp.asana.com",
  "authorization_servers": ["https://mcp.asana.com"],
  "scopes_supported": ["default"],
  "bearer_methods_supported": ["header"],
  "resource_documentation": "https://developers.asana.com/docs/using-asanas-mcp-server",
  "resource_name": "Asana MCP"
}"#;

/// An RFC 9727 API catalog in the JSON linkset form, exercising every relation
/// read plus a per-API anchor.
const API_CATALOG_JSON: &str = r#"{
  "linkset": [
    { "anchor": "https://example.com/.well-known/api-catalog",
      "item": [ { "href": "https://api.example.com/v1" } ] },
    { "anchor": "https://api.example.com/v1",
      "service-desc": [ { "href": "https://docs.example.com/openapi.json",
                          "type": "application/openapi+json" } ],
      "service-doc":  [ { "href": "https://developer.example.com/guide" } ],
      "service-meta": [ { "href": "https://developer.example.com/meta" } ] }
  ]
}"#;

// ── Harness ─────────────────────────────────────────────────────────────────

fn served(wk: WellKnown, origin: &str) -> Url {
    Url::parse(&format!("{origin}{}", wk.path())).unwrap()
}

/// Run the pure decision over `(well-known, body, served-from origin)` legs,
/// every other leg a clean 404.
fn run(domain: &str, legs: &[(WellKnown, &str, &str)]) -> ModuleResult {
    let outcomes = WellKnown::ALL.into_iter().map(|wk| {
        let outcome = legs.iter().find(|(k, ..)| *k == wk).map_or(
            FetchOutcome::Answered,
            |(k, body, origin)| FetchOutcome::Body {
                body: (*body).to_string(),
                served: served(*k, origin),
            },
        );
        (wk, outcome)
    });
    conclude(domain, "scan", outcomes).expect("answered legs never error")
}

fn of_kind<'a>(r: &'a ModuleResult, k: &str) -> Vec<&'a Entity> {
    r.entities
        .iter()
        .filter(|e| e.kind == EntityKind::Other(k.to_string()))
        .collect()
}

fn domains(r: &ModuleResult) -> Vec<&str> {
    r.entities
        .iter()
        .filter(|e| e.kind == EntityKind::Domain)
        .map(|e| e.value.as_str())
        .collect()
}

fn attr<'a>(e: &'a Entity, k: &str) -> Option<&'a str> {
    e.evidence[0].attributes.get(k).map(String::as_str)
}

use super::WellKnown::{
    ApiCatalog, OAuthAuthorizationServer, OAuthProtectedResource, OpenIdConfiguration,
};

// ── Authorization-server metadata ───────────────────────────────────────────

#[test]
fn a_validated_issuer_is_emitted_once_across_both_auth_legs_with_no_self_pivot() {
    let r = run(
        "gitlab.com",
        &[
            (OpenIdConfiguration, GITLAB_META, "https://gitlab.com"),
            (OAuthAuthorizationServer, GITLAB_META, "https://gitlab.com"),
        ],
    );
    let issuers = of_kind(&r, "oauth-issuer");
    assert_eq!(
        issuers.len(),
        1,
        "one issuer, deduplicated across both legs"
    );
    let iss = issuers[0];
    assert_eq!(iss.value, "https://gitlab.com");
    assert!(iss.has_tag("api-discovery") && iss.has_tag("oauth-issuer"));
    assert!(!iss.has_tag("delegated-discovery"));
    assert_eq!(
        attr(iss, "well_known"),
        Some("/.well-known/oauth-authorization-server /.well-known/openid-configuration"),
        "both well-knowns that vouched for it are recorded"
    );
    assert!(attr(iss, "scopes_supported").is_some_and(|s| s.contains("read_api")));
    assert!(attr(iss, "grant_types_supported").is_some_and(|g| g.contains("refresh_token")));
    // Every endpoint is on gitlab.com itself — the engine already scanned it.
    assert!(
        domains(&r).is_empty(),
        "no self-pivot, got {:?}",
        domains(&r)
    );
}

#[test]
fn sibling_endpoint_hosts_become_pivots() {
    let r = run(
        "accounts.google.com",
        &[(
            OpenIdConfiguration,
            GOOGLE_META,
            "https://accounts.google.com",
        )],
    );
    assert_eq!(
        domains(&r),
        [
            "googleapis.com",
            "oauth2.googleapis.com",
            "openidconnect.googleapis.com"
        ],
        "distinct external endpoint hosts in the engine's canonical Domain form \
         (`www.googleapis.com` is born as `googleapis.com`), deduplicated and sorted"
    );
    for e in r.entities.iter().filter(|e| e.kind == EntityKind::Domain) {
        assert!(e.has_tag("api-discovery") && e.has_tag("api-endpoint"));
        assert_eq!(attr(e, "published_by"), Some("accounts.google.com"));
    }
}

/// `Entity::new` canonicalises a Domain by stripping a leading `www.`, so an
/// endpoint on `www.<target>` compared as a raw string passed the self-pivot
/// check and was then BORN as the target — the queried domain echoed back as a
/// "discovered" pivot of itself. Caught by the engine's own canonicaliser
/// turning `www.googleapis.com` into `googleapis.com` in the test above.
#[test]
fn a_www_endpoint_is_never_the_target_echoed_back() {
    let body = r#"{"issuer":"https://acme.com",
                   "authorization_endpoint":"https://www.acme.com/oauth/authorize",
                   "token_endpoint":"https://WWW.Acme.com./oauth/token"}"#;
    let r = run(
        "acme.com",
        &[(OpenIdConfiguration, body, "https://acme.com")],
    );
    assert_eq!(of_kind(&r, "oauth-issuer").len(), 1);
    assert!(
        domains(&r).is_empty(),
        "www.<target> is the target, not a pivot — got {:?}",
        domains(&r)
    );
}

#[test]
fn a_www_target_redirected_to_its_apex_stays_owned() {
    // Target given as `www.acme.com`; its well-known redirects to the apex. Same
    // owner — the apex is not a "third party" the target delegates to.
    let body = r#"{"issuer":"https://acme.com",
                   "token_endpoint":"https://auth.acme.com/token"}"#;
    let r = run(
        "www.acme.com",
        &[(OpenIdConfiguration, body, "https://acme.com")],
    );
    let iss = &of_kind(&r, "oauth-issuer")[0];
    assert!(
        !iss.has_tag("delegated-discovery"),
        "apex of the target is owned"
    );
    assert_eq!(domains(&r), ["auth.acme.com"]);
}

/// The SERVED host is canonicalised too. The auth legs never need it — a
/// trailing-dot origin fails the identifier check first — but the API catalog
/// has no identifier, so its ownership rests on the host comparison alone: a
/// catalog served from `acme.com.` (the absolute form of the same name) is still
/// the owner's, and its hosts are still pivots.
#[test]
fn a_catalog_served_from_the_absolute_form_of_the_target_stays_owned() {
    let catalog = r#"{"linkset":[{"anchor":"https://acme.com/.well-known/api-catalog",
                                   "item":[{"href":"https://api.acme.com/v1"}]}]}"#;
    let r = run("acme.com", &[(ApiCatalog, catalog, "https://acme.com.")]);
    assert_eq!(domains(&r), ["api.acme.com"], "acme.com. is acme.com");
}

#[test]
fn every_endpoint_field_is_read_and_every_host_emitted() {
    let body = r#"{
      "issuer": "https://id.acme.com",
      "authorization_endpoint": "https://ep0.acme.net/a",
      "token_endpoint": "https://ep1.acme.net/t",
      "userinfo_endpoint": "https://ep2.acme.net/u",
      "jwks_uri": "https://ep3.acme.net/j",
      "registration_endpoint": "https://ep4.acme.net/r",
      "revocation_endpoint": "https://ep5.acme.net/rev",
      "introspection_endpoint": "https://ep6.acme.net/i",
      "end_session_endpoint": "https://ep7.acme.net/e",
      "device_authorization_endpoint": "https://ep8.acme.net/d",
      "pushed_authorization_request_endpoint": "https://ep9.acme.net/p",
      "service_documentation": "https://docs.acme.com/oauth"
    }"#;
    let r = run(
        "id.acme.com",
        &[(OpenIdConfiguration, body, "https://id.acme.com")],
    );
    let mut expected: Vec<String> = (0..10).map(|i| format!("ep{i}.acme.net")).collect();
    expected.insert(0, "docs.acme.com".into());
    assert_eq!(
        domains(&r),
        expected,
        "a dropped field silently loses a pivot"
    );
    let refs = of_kind(&r, "api-reference");
    assert_eq!(refs.len(), 1);
    assert_eq!(attr(refs[0], "relation"), Some("service_documentation"));
}

/// RFC 8414 §3.3 / OIDC Discovery §4.3: a document whose issuer is not the
/// identifier its URL was derived from MUST NOT be used. Without this, any
/// domain could publish Google's metadata and be "attributed" Google's
/// infrastructure — a fabricated pivot.
#[test]
fn an_impersonated_issuer_is_never_used() {
    let r = run(
        "evil-lookalike.com",
        &[
            (
                OpenIdConfiguration,
                GOOGLE_META,
                "https://evil-lookalike.com",
            ),
            (
                OAuthAuthorizationServer,
                GOOGLE_META,
                "https://evil-lookalike.com",
            ),
        ],
    );
    assert!(
        r.entities.is_empty(),
        "a mismatched issuer must mint nothing, got {:?}",
        r.entities.iter().map(|e| &e.value).collect::<Vec<_>>()
    );
}

#[test]
fn a_document_without_an_issuer_is_not_metadata() {
    // A SPA config, or endpoint URLs with no issuer: both specs make `issuer`
    // REQUIRED, so neither is mined.
    for body in [
        r#"{"apiBase":"/v2","featureFlags":{"beta":true}}"#,
        r#"{"token_endpoint":"https://auth.other.com/token"}"#,
    ] {
        let r = run(
            "example.com",
            &[(OpenIdConfiguration, body, "https://example.com")],
        );
        assert!(r.entities.is_empty(), "{body} must yield nothing");
    }
}

/// The owner redirecting its discovery document to a hosted IdP (Microsoft
/// Entra shown) is itself an owner assertion — the issuer is validated against
/// the URL that actually served it and recorded as DELEGATED. The IdP's
/// endpoint hosts are not the owner's infrastructure and are never pivots.
#[test]
fn a_cross_site_redirect_records_a_delegated_issuer_without_pivots() {
    let tenant = "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0";
    let entra = format!(
        r#"{{"issuer":"{tenant}",
            "authorization_endpoint":"https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/oauth2/v2.0/authorize",
            "userinfo_endpoint":"https://graph.microsoft.com/oidc/userinfo",
            "scopes_supported":["openid","profile"]}}"#
    );
    let r = run("contoso.com", &[(OpenIdConfiguration, &entra, tenant)]);
    let issuers = of_kind(&r, "oauth-issuer");
    assert_eq!(issuers.len(), 1);
    assert_eq!(
        issuers[0].value, tenant,
        "the Entra tenant is the pivot-worthy fact"
    );
    assert!(issuers[0].has_tag("delegated-discovery"));
    assert_eq!(attr(issuers[0], "delegated"), Some("true"));
    assert!(
        attr(issuers[0], "scopes_supported").is_none(),
        "the IdP's scopes are not facts about contoso.com"
    );
    assert!(
        domains(&r).is_empty(),
        "graph.microsoft.com is not contoso.com's infrastructure, got {:?}",
        domains(&r)
    );
}

#[test]
fn a_redirect_to_the_owners_own_subdomain_stays_owned() {
    let body = r#"{"issuer":"https://www.acme.com",
                   "token_endpoint":"https://auth.acme.com/token"}"#;
    let r = run(
        "acme.com",
        &[(OpenIdConfiguration, body, "https://www.acme.com")],
    );
    let iss = &of_kind(&r, "oauth-issuer")[0];
    assert!(!iss.has_tag("delegated-discovery"));
    assert_eq!(domains(&r), ["auth.acme.com"]);
}

// ── Protected-resource metadata (RFC 9728 — MCP servers) ────────────────────

#[test]
fn a_protected_resource_names_its_api_and_its_authorization_servers() {
    let r = run(
        "mcp.atlassian.com",
        &[(
            OAuthProtectedResource,
            ATLASSIAN_PRM,
            "https://mcp.atlassian.com",
        )],
    );
    let res = of_kind(&r, "oauth-protected-resource");
    assert_eq!(res.len(), 1);
    // The trailing-slash `resource` validates against the slash-less origin.
    assert_eq!(res[0].value, "https://mcp.atlassian.com");
    assert_eq!(
        attr(res[0], "authorization_servers"),
        Some("https://auth.atlassian.com/VCeDsk8ZHncYF1g234fKtc4lNipbBhu3"),
        "the authorization server keeps its tenant path"
    );
    assert!(attr(res[0], "scopes_supported").is_some_and(|s| s.contains("read:jira-work")));
    assert_eq!(domains(&r), ["auth.atlassian.com"]);
}

#[test]
fn a_protected_resource_carries_its_name_and_documentation() {
    let r = run(
        "mcp.asana.com",
        &[(OAuthProtectedResource, ASANA_PRM, "https://mcp.asana.com")],
    );
    let res = &of_kind(&r, "oauth-protected-resource")[0];
    assert_eq!(attr(res, "resource_name"), Some("Asana MCP"));
    let refs = of_kind(&r, "api-reference");
    assert_eq!(refs.len(), 1);
    assert_eq!(
        refs[0].value,
        "https://developers.asana.com/docs/using-asanas-mcp-server"
    );
    assert_eq!(attr(refs[0], "relation"), Some("resource_documentation"));
    // The self-hosted authorization server is the target itself — no pivot —
    // while the documentation host is.
    assert_eq!(domains(&r), ["developers.asana.com"]);
}

#[test]
fn a_mismatched_or_redirected_protected_resource_is_never_used() {
    let other = r#"{"resource":"https://mcp.other.com",
                    "authorization_servers":["https://auth.other.com"]}"#;
    let r = run(
        "mcp.acme.com",
        &[(OAuthProtectedResource, other, "https://mcp.acme.com")],
    );
    assert!(r.entities.is_empty(), "resource ≠ served identifier");
    // Self-consistent, but reached by a cross-site redirect: some other
    // party's API, not a fact about the target.
    let r = run(
        "mcp.acme.com",
        &[(OAuthProtectedResource, other, "https://mcp.other.com")],
    );
    assert!(r.entities.is_empty(), "cross-site protected resource");
}

// ── Declared authorization servers (the path-bearing follow-up) ─────────────

/// Stripe's MCP server (RFC 9728): the authorization server is on a sibling
/// host and its issuer carries a PATH, so its metadata lives at the RFC 8414
/// path-inserted URL — unreachable from a bare-Domain pivot.
const STRIPE_PRM: &str = r#"{"resource":"https://mcp.stripe.com",
                             "authorization_servers":["https://access.stripe.com/mcp"]}"#;

/// Stripe's authorization-server metadata as served at
/// `https://access.stripe.com/.well-known/oauth-authorization-server/mcp`.
const STRIPE_AS: &str = r#"{
  "issuer": "https://access.stripe.com/mcp",
  "authorization_endpoint": "https://access.stripe.com/mcp/oauth2/authorize",
  "token_endpoint": "https://access.stripe.com/mcp/oauth2/token",
  "registration_endpoint": "https://access.stripe.com/mcp/oauth2/register",
  "grant_types_supported": ["authorization_code", "refresh_token"]
}"#;

fn collect_legs(domain: &str, legs: &[(WellKnown, &str, &str)]) -> Collected {
    let outcomes = legs.iter().map(|(wk, body, origin)| {
        (
            *wk,
            FetchOutcome::Body {
                body: (*body).to_string(),
                served: served(*wk, origin),
            },
        )
    });
    collect(domain, outcomes)
}

#[test]
fn a_path_bearing_declared_server_is_followed_at_its_spec_urls() {
    let c = collect_legs(
        "mcp.stripe.com",
        &[(OAuthProtectedResource, STRIPE_PRM, "https://mcp.stripe.com")],
    );
    let follow = c.found.declared_metadata_urls();
    let urls: Vec<(WellKnown, &str)> = follow.iter().map(|f| (f.wk, f.url.as_str())).collect();
    assert_eq!(
        urls,
        [
            (
                OAuthAuthorizationServer,
                "https://access.stripe.com/.well-known/oauth-authorization-server/mcp"
            ),
            (
                OpenIdConfiguration,
                "https://access.stripe.com/mcp/.well-known/openid-configuration"
            ),
        ],
        "RFC 8414 inserts the well-known before the path; OIDC appends it"
    );
    assert!(
        follow
            .iter()
            .all(|f| f.resource == "https://mcp.stripe.com")
    );
}

#[test]
fn path_less_or_already_validated_servers_are_not_followed() {
    // Asana's authorization server is the target itself (path-less, and read in
    // the first stage); a path-less sibling is reached by the Domain pivot.
    let prm = r#"{"resource":"https://mcp.acme.com",
                  "authorization_servers":["https://mcp.acme.com","https://auth.acme.com/"]}"#;
    let c = collect_legs(
        "mcp.acme.com",
        &[(OAuthProtectedResource, prm, "https://mcp.acme.com")],
    );
    assert!(c.found.declared_metadata_urls().is_empty());

    // A path-bearing server whose issuer the first stage already validated.
    let meta = r#"{"issuer":"https://mcp.acme.com/t1"}"#;
    let prm = r#"{"resource":"https://mcp.acme.com","authorization_servers":["https://mcp.acme.com/t1"]}"#;
    let mut c = collect_legs(
        "mcp.acme.com",
        &[(OAuthProtectedResource, prm, "https://mcp.acme.com")],
    );
    c.found.ingest(
        OAuthAuthorizationServer,
        meta,
        &Url::parse("https://mcp.acme.com/.well-known/oauth-authorization-server/t1").unwrap(),
        "mcp.acme.com",
    );
    assert!(c.found.declared_metadata_urls().is_empty());
}

#[test]
fn a_followed_declared_server_is_validated_and_attributed_to_its_resource() {
    let mut c = collect_legs(
        "mcp.stripe.com",
        &[(OAuthProtectedResource, STRIPE_PRM, "https://mcp.stripe.com")],
    );
    let follow = c.found.declared_metadata_urls();
    let rfc8414 = follow
        .iter()
        .find(|f| f.wk == OAuthAuthorizationServer)
        .unwrap();
    c.follow_up(rfc8414, STRIPE_AS, &Url::parse(&rfc8414.url).unwrap());
    let r = c.finish("mcp.stripe.com", "scan").unwrap();

    let iss = of_kind(&r, "oauth-issuer");
    assert_eq!(iss.len(), 1);
    assert_eq!(iss[0].value, "https://access.stripe.com/mcp");
    assert!(iss[0].has_tag("declared-authorization-server"));
    assert!(!iss[0].has_tag("delegated-discovery"));
    assert_eq!(attr(iss[0], "declared_by"), Some("https://mcp.stripe.com"));
    // access.stripe.com is a pivot through the protected resource's own
    // declaration; the followed server adds no further hosts of its own.
    assert_eq!(domains(&r), ["access.stripe.com"]);
}

#[test]
fn a_followed_server_answering_for_another_issuer_is_not_used() {
    // Declared `…/t1`, but the served document (a redirect to another tenant,
    // or a misconfiguration) validates as `…/t2`. Self-consistent — and still
    // not the server the resource trusts.
    let prm = r#"{"resource":"https://mcp.acme.com",
                  "authorization_servers":["https://auth.other.com/t1"]}"#;
    let mut c = collect_legs(
        "mcp.acme.com",
        &[(OAuthProtectedResource, prm, "https://mcp.acme.com")],
    );
    let follow = c.found.declared_metadata_urls();
    let f = follow
        .iter()
        .find(|f| f.wk == OAuthAuthorizationServer)
        .unwrap();
    c.follow_up(
        f,
        r#"{"issuer":"https://auth.other.com/t2"}"#,
        &Url::parse("https://auth.other.com/.well-known/oauth-authorization-server/t2").unwrap(),
    );
    let r = c.finish("mcp.acme.com", "scan").unwrap();
    assert!(of_kind(&r, "oauth-issuer").is_empty());
}

#[test]
fn declared_server_follow_ups_are_bounded_but_nothing_is_dropped() {
    let servers: Vec<String> = (0..10)
        .map(|i| format!("\"https://as{i}.other.com/t\""))
        .collect();
    let prm = format!(
        r#"{{"resource":"https://mcp.acme.com","authorization_servers":[{}]}}"#,
        servers.join(",")
    );
    let c = collect_legs(
        "mcp.acme.com",
        &[(OAuthProtectedResource, &prm, "https://mcp.acme.com")],
    );
    let follow = c.found.declared_metadata_urls();
    let distinct: BTreeSet<&str> = follow.iter().map(|f| f.issuer.as_str()).collect();
    assert_eq!(distinct.len(), MAX_DECLARED_SERVERS, "requests are bounded");
    assert_eq!(
        follow.len(),
        2 * MAX_DECLARED_SERVERS,
        "two spec URLs per server"
    );

    let r = c.finish("mcp.acme.com", "scan").unwrap();
    assert_eq!(
        domains(&r).len(),
        10,
        "every declared server's host is still a pivot"
    );
    let res = &of_kind(&r, "oauth-protected-resource")[0];
    assert_eq!(
        attr(res, "authorization_servers").map(|s| s.split(' ').count()),
        Some(10),
        "every declared server is still recorded"
    );
}

#[test]
fn a_private_declared_server_is_never_followed() {
    let prm = r#"{"resource":"https://mcp.acme.com",
                  "authorization_servers":["https://10.0.0.1/tenant","https://db.internal/t"]}"#;
    let c = collect_legs(
        "mcp.acme.com",
        &[(OAuthProtectedResource, prm, "https://mcp.acme.com")],
    );
    assert!(c.found.declared_metadata_urls().is_empty());
}

// ── API catalog (RFC 9727) ──────────────────────────────────────────────────

#[test]
fn an_api_catalog_yields_every_relation_and_its_hosts() {
    let r = run(
        "example.com",
        &[(ApiCatalog, API_CATALOG_JSON, "https://example.com")],
    );
    let rel = |url: &str| {
        of_kind(&r, "api-reference")
            .into_iter()
            .find(|e| e.value == url)
            .and_then(|e| attr(e, "relation"))
    };
    assert_eq!(
        rel("https://api.example.com/v1"),
        Some("item"),
        "item wins over anchor"
    );
    assert_eq!(
        rel("https://docs.example.com/openapi.json"),
        Some("service-desc")
    );
    assert_eq!(
        rel("https://developer.example.com/guide"),
        Some("service-doc")
    );
    assert_eq!(
        rel("https://developer.example.com/meta"),
        Some("service-meta")
    );
    assert_eq!(
        of_kind(&r, "api-reference").len(),
        4,
        "the catalog's own anchor is not an API reference"
    );
    assert_eq!(
        domains(&r),
        [
            "api.example.com",
            "developer.example.com",
            "docs.example.com"
        ]
    );
}

#[test]
fn an_api_catalog_in_the_linkset_text_form_is_read() {
    let text = "<https://api.acme.com/v2>; rel=\"item\",\n \
                <https://docs.acme.com/v2/openapi.yaml>; rel=\"service-desc\"; type=\"application/yaml\",\n \
                <https://acme.com/about>; rel=\"author\",\n \
                <https://status.acme.com>; rel=item";
    let r = run("acme.com", &[(ApiCatalog, text, "https://acme.com")]);
    let refs: Vec<(&str, &str)> = of_kind(&r, "api-reference")
        .into_iter()
        .map(|e| (e.value.as_str(), attr(e, "relation").unwrap()))
        .collect();
    assert_eq!(
        refs,
        [
            ("https://api.acme.com/v2", "item"),
            ("https://docs.acme.com/v2/openapi.yaml", "service-desc"),
            ("https://status.acme.com/", "item"),
        ],
        "known relations only (rel=author ignored), quoted or bare"
    );
}

#[test]
fn an_html_page_at_the_catalog_path_yields_nothing() {
    let html = "<!DOCTYPE html><html><head><link rel=\"stylesheet\" href=\"https://cdn.acme.com/a.css\">\
                </head><body><a href=\"https://acme.com/x\">x</a></body></html>";
    let r = run("acme.com", &[(ApiCatalog, html, "https://acme.com")]);
    assert!(r.entities.is_empty());
}

// ── SSRF: a hostile document can never mint an internal host ────────────────

#[test]
fn private_and_special_use_endpoint_hosts_are_never_minted() {
    let hostile = r#"{
      "issuer": "https://hostile.com",
      "authorization_endpoint": "https://public-sibling.com/authorize",
      "token_endpoint": "http://169.254.169.254/latest/meta-data/",
      "userinfo_endpoint": "https://10.0.0.5/userinfo",
      "jwks_uri": "https://2130706433/keys",
      "registration_endpoint": "https://db.internal/register",
      "revocation_endpoint": "https://localhost/revoke",
      "introspection_endpoint": "https://[::1]/introspect",
      "end_session_endpoint": "http://plain-http.com/logout",
      "device_authorization_endpoint": "https://intranet/device"
    }"#;
    let r = run(
        "hostile.com",
        &[(OpenIdConfiguration, hostile, "https://hostile.com")],
    );
    assert_eq!(
        domains(&r),
        ["public-sibling.com"],
        "only the public https sibling survives"
    );
}

// ── Identifier derivation (the spec rules, unit-level) ──────────────────────

#[test]
fn identifiers_canonicalise_and_derive_per_spec() {
    // Canonical form: trailing slash and default port are not identity.
    assert_eq!(
        canonical_identifier("https://h.com/").as_deref(),
        Some("https://h.com")
    );
    assert_eq!(
        canonical_identifier("https://H.com:443").as_deref(),
        Some("https://h.com")
    );
    assert_eq!(
        canonical_identifier("https://h.com/tenant/").as_deref(),
        Some("https://h.com/tenant")
    );
    // Not identifiers at all (RFC 8414 §2 / RFC 9728 §2).
    for bad in [
        "http://h.com",
        "https://h.com?x=1",
        "https://h.com#f",
        "https://u@h.com",
        "not a url",
    ] {
        assert!(canonical_identifier(bad).is_none(), "{bad}");
    }

    let url = |s: &str| Url::parse(s).unwrap();
    // OIDC appends the suffix; RFC 8414 / 9728 insert it.
    assert_eq!(
        OpenIdConfiguration.expected_identifier(&url(
            "https://h.com/realms/x/.well-known/openid-configuration"
        )),
        Some("https://h.com/realms/x".into())
    );
    assert_eq!(
        OAuthAuthorizationServer.expected_identifier(&url(
            "https://h.com/.well-known/oauth-authorization-server/t1"
        )),
        Some("https://h.com/t1".into())
    );
    assert_eq!(
        OAuthProtectedResource
            .expected_identifier(&url("https://h.com/.well-known/oauth-protected-resource")),
        Some("https://h.com".into())
    );
    // A body served from anywhere else (a redirect to a login page, plain http)
    // has no valid identifier, so nothing in it can validate.
    assert_eq!(
        OpenIdConfiguration.expected_identifier(&url("https://h.com/login")),
        None
    );
    assert_eq!(
        OpenIdConfiguration
            .expected_identifier(&url("http://h.com/.well-known/openid-configuration")),
        None
    );
    assert_eq!(
        ApiCatalog.expected_identifier(&url("https://h.com/.well-known/api-catalog")),
        None
    );
}

#[test]
fn metadata_redirected_to_a_non_well_known_url_is_not_used() {
    // The owner's well-known 302s to a generic page that happens to be JSON with
    // a matching-looking issuer: the served URL is not a metadata location.
    let body = r#"{"issuer":"https://acme.com","token_endpoint":"https://auth.acme.com/t"}"#;
    let outcomes = [(
        OpenIdConfiguration,
        FetchOutcome::Body {
            body: body.into(),
            served: Url::parse("https://acme.com/login?next=/").unwrap(),
        },
    )];
    let r = conclude("acme.com", "scan", outcomes).unwrap();
    assert!(r.entities.is_empty());
}

// ── Outcome typing: outage vs clean negative ────────────────────────────────

#[test]
fn every_leg_prevented_is_an_outage_never_a_clean_negative() {
    let all = |f: fn() -> FetchOutcome| WellKnown::ALL.into_iter().map(move |wk| (wk, f()));
    let err = conclude("acme.com", "s", all(|| FetchOutcome::TransportFailed))
        .expect_err("four transport failures must not read as 'publishes nothing'");
    assert!(matches!(err, Error::Module { .. }), "got {err:?}");

    // A wall is preferred over the generic message: it names what happened.
    let err = conclude(
        "acme.com",
        "s",
        all(|| FetchOutcome::Blocked(Error::BotChallenge("cf".into()))),
    )
    .expect_err("four walls are an outage");
    assert!(matches!(err, Error::BotChallenge(_)), "got {err:?}");

    // One genuine answer proves the site was reached: the rest's silence is a
    // clean negative.
    let mixed = [
        (OpenIdConfiguration, FetchOutcome::TransportFailed),
        (
            OAuthAuthorizationServer,
            FetchOutcome::Blocked(Error::BotChallenge("cf".into())),
        ),
        (OAuthProtectedResource, FetchOutcome::TransportFailed),
        (ApiCatalog, FetchOutcome::Answered),
    ];
    let r = conclude("acme.com", "s", mixed).expect("reached once → clean negative");
    assert!(r.entities.is_empty());

    // An ordinary site: 404 everywhere.
    let r = conclude("acme.com", "s", all(|| FetchOutcome::Answered)).unwrap();
    assert!(r.entities.is_empty());
}

#[test]
fn findings_survive_when_the_other_legs_are_walled() {
    let outcomes = [
        (
            OpenIdConfiguration,
            FetchOutcome::Body {
                body: GITLAB_META.into(),
                served: served(OpenIdConfiguration, "https://gitlab.com"),
            },
        ),
        (
            OAuthAuthorizationServer,
            FetchOutcome::Blocked(Error::BotChallenge("cf".into())),
        ),
        (OAuthProtectedResource, FetchOutcome::TransportFailed),
        (ApiCatalog, FetchOutcome::TransportFailed),
    ];
    let r = conclude("gitlab.com", "s", outcomes).expect("a finding is never discarded");
    assert_eq!(of_kind(&r, "oauth-issuer").len(), 1);
}

// ── Module contract ─────────────────────────────────────────────────────────

#[test]
fn is_free_web_module() {
    let m = ApiDiscovery;
    assert!(matches!(m.cost(), crate::core::module::ModuleCost::Free));
    assert_eq!(m.category(), ModuleCategory::Web);
    assert!(!m.attack_techniques().is_empty());
    assert!(m.accepts(&Target::new(TargetKind::Domain, "example.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Username, "alice")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "8.8.8.8")));
    assert!(m.max_timeout_ms() > 3_000);
}

/// A Cloudflare interstitial as the runner actually received one — the exact
/// fingerprints `util::html::is_challenge_document` keys on.
const CF_CHALLENGE_PAGE: &str = "<!DOCTYPE html><html lang=\"en-US\"><head>\
    <title>Just a moment...</title></head><body>\
    <noscript>Enable JavaScript and cookies to continue</noscript>\
    <script src=\"/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1?ray=9d1f2c3b4a5e6f70\"></script>\
    </body></html>";

/// A 2xx anti-bot wall must be typed `Blocked`, never folded into the ordinary
/// negative — the discarded-typed-error shape `app_links` had to fix
/// (REQ-APPLINKS-001). Driven through the real HTTP path against the loopback
/// server, so `document_or_challenge` is genuinely exercised, and the served URL
/// is captured for the identifier checks.
#[tokio::test]
async fn a_wall_is_not_an_answer_about_api_discovery() {
    use crate::util::http::test_server::{Canned, serve};
    let base = serve(vec![
        Canned::html(200, CF_CHALLENGE_PAGE),
        Canned::text(404, "Not Found"),
        Canned::json(200, "  \n"),
        Canned::json(200, GITLAB_META),
    ])
    .await;
    let (bus, _rx) = tokio::sync::broadcast::channel(1);
    let ctx = ModuleContext {
        scan_id: "t".into(),
        bus,
        http: reqwest::Client::new(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
    };
    let url = format!("{base}/.well-known/openid-configuration");

    match fetch_text(&ctx, &url).await {
        FetchOutcome::Blocked(Error::BotChallenge(_)) => {}
        _ => panic!("a 200 anti-bot wall must be Blocked(BotChallenge)"),
    }
    assert!(
        matches!(fetch_text(&ctx, &url).await, FetchOutcome::Answered),
        "a 404 is the ordinary negative"
    );
    assert!(
        matches!(fetch_text(&ctx, &url).await, FetchOutcome::Answered),
        "a whitespace-only 2xx is the ordinary negative too"
    );
    match fetch_text(&ctx, &url).await {
        FetchOutcome::Body { body, served } => {
            assert!(body.contains("gitlab.com"));
            assert_eq!(served.as_str(), url, "the answering URL is carried");
        }
        _ => panic!("a real metadata body must still be read"),
    }
}

/// Live end-to-end proof against REAL domains — no mock. Ignored by default
/// (network); run with
/// `cargo test --lib api_discovery_live -- --ignored --nocapture`.
///
/// Uses the PRODUCTION client (`build_client`), never `reqwest::Client::new()`.
/// The two do not take the same route: the plain client honours `HTTPS_PROXY`,
/// while the engine's SSRF-guarded client is `no_proxy()` and dials direct.
/// Observed 2026-09-23: `mcp.atlassian.com` serves its protected-resource
/// document (200) to the proxied route and `404` to the direct one — a
/// vantage-dependent provider, which a live test on the plain client reported
/// as working while every production scan from the same machine got nothing.
/// A live test on a different client proves a different path.
///
/// Every target here was checked to answer on the direct route. `mcp.stripe.com`
/// exercises both stages: the protected resource, then the declared,
/// path-bearing authorization server followed to its RFC 8414 URL.
#[tokio::test]
#[ignore = "hits live well-known endpoints; run manually"]
async fn api_discovery_live() {
    let (bus, _rx) = tokio::sync::broadcast::channel(1);
    let ctx = ModuleContext {
        scan_id: "live".into(),
        bus,
        http: crate::util::http::build_client(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
    };
    let scan = |domain: &'static str| {
        let ctx = ctx.clone();
        async move {
            let r = ApiDiscovery
                .process(&Target::new(TargetKind::Domain, domain), &ctx)
                .await
                .unwrap_or_else(|e| panic!("{domain}: {e}"));
            for e in &r.entities {
                eprintln!("  {domain}: {:?} {}", e.kind, e.value);
            }
            r
        }
    };

    let r = scan("gitlab.com").await;
    assert!(
        of_kind(&r, "oauth-issuer")
            .iter()
            .any(|e| e.value == "https://gitlab.com")
    );

    let r = scan("accounts.google.com").await;
    assert!(
        of_kind(&r, "oauth-issuer")
            .iter()
            .any(|e| e.value == "https://accounts.google.com")
    );
    assert!(
        domains(&r).contains(&"oauth2.googleapis.com"),
        "sibling endpoint pivot"
    );

    let r = scan("mcp.stripe.com").await;
    assert!(
        of_kind(&r, "oauth-protected-resource")
            .iter()
            .any(|e| e.value == "https://mcp.stripe.com")
    );
    let declared = of_kind(&r, "oauth-issuer");
    assert!(
        declared
            .iter()
            .any(|e| e.value == "https://access.stripe.com/mcp"
                && e.has_tag("declared-authorization-server")),
        "the declared path-bearing authorization server is followed and validated"
    );

    let r = scan("mcp.asana.com").await;
    let res = of_kind(&r, "oauth-protected-resource");
    assert!(
        res.iter()
            .any(|e| attr(e, "resource_name") == Some("Asana MCP"))
    );
}
