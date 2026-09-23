//! Domain → its published **API / authorization surface**, read from the
//! standards-based discovery well-knowns the domain owner serves. Free, no API
//! key.
//!
//! A programmable service advertises itself in documents it publishes at fixed
//! `/.well-known/` paths, so reading them maps a domain to the API and identity
//! infrastructure behind it — a pivot the keyless OSINT stacks don't surface:
//!
//! * **OpenID Connect Discovery 1.0** — `/.well-known/openid-configuration`.
//! * **OAuth 2.0 Authorization Server Metadata (RFC 8414)** —
//!   `/.well-known/oauth-authorization-server`. Both carry an `issuer` (the
//!   authorization server's stable identity) and the URLs of its endpoints;
//!   every endpoint host that differs from the queried domain is a sibling the
//!   owner declares runs their auth.
//! * **OAuth 2.0 Protected Resource Metadata (RFC 9728)** —
//!   `/.well-known/oauth-protected-resource`. Names the protected API
//!   (`resource`, `resource_name`), the authorization servers it trusts, and its
//!   documentation. The Model Context Protocol's authorization spec makes every
//!   remote MCP server publish it, so this is where agent-facing APIs announce
//!   themselves.
//! * **API Catalog (RFC 9727)** — `/.well-known/api-catalog`, an RFC 9264
//!   linkset (JSON or the `application/linkset` text form) listing the org's
//!   APIs (`item`) and their descriptions (`service-desc`, `service-doc`,
//!   `service-meta`).
//!
//! **Validation is spec-exact, not best-effort.** RFC 8414 §3.3, OIDC Discovery
//! §4.3 and RFC 9728 §3.3 all require the document's `issuer` / `resource` to be
//! identical to the identifier its well-known URL was derived from, and say a
//! mismatched document MUST NOT be used. HSE enforces that against the URL that
//! actually *served* the body (after redirects), so a domain that publishes
//! someone else's metadata — or points its well-known at a third party — can
//! never have that party's infrastructure attributed to it. Endpoint hosts are
//! minted as pivots only from documents served by the domain itself or a host
//! under it, and only after the shared SSRF preflight
//! ([`url_host_is_private`]) has refused private and special-use hosts.
//!
//! An ordinary site 404s on all four (a clean miss). No mock: every document is
//! fetched live from the domain's own well-known paths.

use std::collections::{BTreeMap, BTreeSet};

use async_trait::async_trait;
use serde::Deserialize;
use url::Url;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::domains::is_or_subdomain_of;
use crate::util::http::{RequestBuilderExt, http_status_error, read_text};
use crate::util::preflight::url_host_is_private;

const SRC: &str = "api_discovery";

/// Domain → OAuth/OIDC issuer, protected-resource identity, API/auth endpoint
/// hosts and published API references, from the domain's own discovery
/// well-knowns (see the module docs).
pub struct ApiDiscovery;

/// The four discovery well-knowns this module reads, in fetch order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WellKnown {
    OpenIdConfiguration,
    OAuthAuthorizationServer,
    OAuthProtectedResource,
    ApiCatalog,
}

impl WellKnown {
    const ALL: [Self; 4] = [
        Self::OpenIdConfiguration,
        Self::OAuthAuthorizationServer,
        Self::OAuthProtectedResource,
        Self::ApiCatalog,
    ];

    fn path(self) -> &'static str {
        match self {
            Self::OpenIdConfiguration => "/.well-known/openid-configuration",
            Self::OAuthAuthorizationServer => "/.well-known/oauth-authorization-server",
            Self::OAuthProtectedResource => "/.well-known/oauth-protected-resource",
            Self::ApiCatalog => "/.well-known/api-catalog",
        }
    }

    /// The identifier a document served from `served` must declare to be
    /// usable, per its spec's derivation rule — or `None` when `served` is not a
    /// URL this well-known can validly live at (then nothing in it is used).
    ///
    /// * OIDC Discovery §4 **appends** the suffix to the issuer, so the issuer is
    ///   the served URL with the suffix stripped from the end of the path.
    /// * RFC 8414 §3.1 and RFC 9728 §3.1 **insert** the suffix between host and
    ///   path, so the identifier is the origin plus whatever follows the suffix.
    /// * The API catalog is a plain pointer document with no self-identifier.
    fn expected_identifier(self, served: &Url) -> Option<String> {
        if served.scheme() != "https" || served.query().is_some() {
            return None;
        }
        let origin = served.origin().ascii_serialization();
        let path = served.path();
        let rest = match self {
            Self::OpenIdConfiguration => path.strip_suffix(self.path())?,
            Self::OAuthAuthorizationServer | Self::OAuthProtectedResource => {
                // Inserted as whole path segments: what follows the suffix is
                // empty or a further `/segment`. A bare `strip_prefix` read
                // `/.well-known/oauth-authorization-server.google.com` as the
                // suffix plus `.google.com`, deriving the identifier
                // `https://<host>.google.com` — an issuer on ANOTHER host,
                // validated by a URL that is no derivation of it.
                let rest = path.strip_prefix(self.path())?;
                if !(rest.is_empty() || rest.starts_with('/')) {
                    return None;
                }
                rest
            }
            Self::ApiCatalog => return None,
        };
        canonical_identifier(&format!("{origin}{rest}"))
    }
}

/// OAuth 2.0 Authorization Server Metadata (RFC 8414) / OpenID Connect
/// Discovery — the fields HSE pivots on. `issuer` is REQUIRED by both specs; a
/// document without a valid one is not used.
#[derive(Deserialize, Default)]
#[serde(default)]
struct AuthMetadata {
    issuer: Option<String>,
    authorization_endpoint: Option<String>,
    token_endpoint: Option<String>,
    userinfo_endpoint: Option<String>,
    jwks_uri: Option<String>,
    registration_endpoint: Option<String>,
    revocation_endpoint: Option<String>,
    introspection_endpoint: Option<String>,
    end_session_endpoint: Option<String>,
    device_authorization_endpoint: Option<String>,
    pushed_authorization_request_endpoint: Option<String>,
    service_documentation: Option<String>,
    op_policy_uri: Option<String>,
    op_tos_uri: Option<String>,
    scopes_supported: Vec<String>,
    grant_types_supported: Vec<String>,
}

impl AuthMetadata {
    /// Every endpoint URL the document carries. `issuer` is an identity, emitted
    /// on its own; the documentation and policy URLs are API references
    /// ([`Self::reference_urls`]), not endpoints.
    fn endpoint_urls(&self) -> impl Iterator<Item = &str> {
        [
            &self.authorization_endpoint,
            &self.token_endpoint,
            &self.userinfo_endpoint,
            &self.jwks_uri,
            &self.registration_endpoint,
            &self.revocation_endpoint,
            &self.introspection_endpoint,
            &self.end_session_endpoint,
            &self.device_authorization_endpoint,
            &self.pushed_authorization_request_endpoint,
        ]
        .into_iter()
        .filter_map(|o| o.as_deref())
    }

    /// Every URL RFC 8414 §2 defines for documenting the service to a human —
    /// its documentation, policy and terms — with the field name as relation.
    fn reference_urls(&self) -> impl Iterator<Item = (&str, &'static str)> {
        [
            (&self.service_documentation, "service_documentation"),
            (&self.op_policy_uri, "op_policy_uri"),
            (&self.op_tos_uri, "op_tos_uri"),
        ]
        .into_iter()
        .filter_map(|(o, rel)| o.as_deref().map(|u| (u, rel)))
    }
}

/// OAuth 2.0 Protected Resource Metadata (RFC 9728). `resource` is REQUIRED.
#[derive(Deserialize, Default)]
#[serde(default)]
struct ResourceMetadata {
    resource: Option<String>,
    authorization_servers: Vec<String>,
    jwks_uri: Option<String>,
    scopes_supported: Vec<String>,
    resource_name: Option<String>,
    resource_documentation: Option<String>,
    resource_policy_uri: Option<String>,
    resource_tos_uri: Option<String>,
}

impl ResourceMetadata {
    /// Every URL RFC 9728 §2 defines for documenting the resource to a human —
    /// its documentation, policy and terms — with the field name as relation.
    fn reference_urls(&self) -> impl Iterator<Item = (&str, &'static str)> {
        [
            (&self.resource_documentation, "resource_documentation"),
            (&self.resource_policy_uri, "resource_policy_uri"),
            (&self.resource_tos_uri, "resource_tos_uri"),
        ]
        .into_iter()
        .filter_map(|(o, rel)| o.as_deref().map(|u| (u, rel)))
    }
}

/// RFC 9727 API catalog in the RFC 9264 `application/linkset+json` form.
#[derive(Deserialize, Default)]
#[serde(default)]
struct Linkset {
    linkset: Vec<LinkContext>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct LinkContext {
    anchor: Option<String>,
    item: Vec<LinkTarget>,
    #[serde(rename = "service-desc")]
    service_desc: Vec<LinkTarget>,
    #[serde(rename = "service-doc")]
    service_doc: Vec<LinkTarget>,
    #[serde(rename = "service-meta")]
    service_meta: Vec<LinkTarget>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct LinkTarget {
    href: Option<String>,
}

/// The link relations of an API catalog that point at an API or its
/// description (RFC 9727 §4; RFC 8631 for the `service-*` relations).
const CATALOG_RELATIONS: [&str; 4] = ["item", "service-desc", "service-doc", "service-meta"];

/// A validated protected resource (RFC 9728).
#[derive(Default)]
struct ProtectedResource {
    name: Option<String>,
    authorization_servers: BTreeSet<String>,
    scopes: BTreeSet<String>,
    served_from: String,
}

/// A validated authorization server / OIDC provider.
#[derive(Default)]
struct Issuer {
    /// Which well-knowns vouched for it (a server usually serves both).
    sources: BTreeSet<&'static str>,
    scopes: BTreeSet<String>,
    grants: BTreeSet<String>,
    served_from: String,
    /// Some document naming this issuer was served by the queried domain (or a
    /// host under it). `false` means every one was reached through a redirect
    /// off the domain — the owner delegates discovery to a third party
    /// (typically its hosted IdP) — or it was followed from a declaration.
    owned: bool,
    /// Protected resources (RFC 9728) of this domain that name it in their
    /// `authorization_servers`, when its metadata was followed from there.
    declared_by: BTreeSet<String>,
}

/// One authorization server a protected resource declared, and one of its
/// spec-derived metadata URLs to follow (see
/// [`Discovery::declared_metadata_urls`]).
struct FollowUp {
    resource: String,
    issuer: String,
    wk: WellKnown,
    url: String,
}

/// At most this many distinct declared authorization servers are followed per
/// target. A bound on REQUESTS, not on output: a hostile protected-resource
/// document listing thousands of servers must not turn one dispatch into a
/// fan-out, and every declared server is still recorded (evidence + host pivot)
/// whether or not it was followed. Real documents list one.
const MAX_DECLARED_SERVERS: usize = 4;

/// At most this many endpoint/API host pivots, and this many API references,
/// are emitted per target — the same order as `sitemap`'s `MAX_URLS`. Every
/// document read here is controlled by the target, and the engine checks its
/// `max_entities` budget only BETWEEN dispatches, absorbing one module's result
/// whole: an unbounded 32 MiB catalog would mint hundreds of thousands of
/// high-confidence entities in a single call. Real documents yield single
/// digits (Google's: 4 hosts, 1 reference). What is dropped is declared through
/// `ModuleResult::mark_truncated`, so coverage never reads a capped answer as
/// the whole one.
const MAX_PIVOT_HOSTS: usize = 200;
const MAX_REFERENCES: usize = 200;

/// Everything collected across the four legs, emitted once. Every bucket is a
/// sorted map/set, so output is deduplicated and deterministic: OIDC and
/// OAuth-AS metadata are usually the same document, and one host appears in
/// many endpoints.
#[derive(Default)]
struct Discovery {
    issuers: BTreeMap<String, Issuer>,
    resources: BTreeMap<String, ProtectedResource>,
    pivot_hosts: BTreeSet<String>,
    /// API reference URL → the relation it was published under.
    references: BTreeMap<String, &'static str>,
    /// Documents that decoded but failed their spec's identifier check — kept
    /// for the debug log, never used.
    rejected: usize,
}

impl Discovery {
    /// Fold one served document into the collection. `served` is the URL that
    /// actually answered (after redirects); `site` is the queried target in the
    /// engine's canonical Domain form ([`canonical_host`]).
    fn ingest(&mut self, wk: WellKnown, body: &str, served: &Url, site: &str) {
        // Endpoint hosts are pivots only when the site itself (or a host under
        // it) served the document. A redirect to a third party is the owner
        // delegating discovery; the third party's infrastructure is not theirs.
        // Compared canonically, so `www.x` → `x` (or back) stays the owner's.
        let owned = served_by(served, site);
        match wk {
            WellKnown::OpenIdConfiguration | WellKnown::OAuthAuthorizationServer => {
                self.ingest_auth(wk, body, served, site, owned);
            }
            WellKnown::OAuthProtectedResource => {
                self.ingest_resource(body, served, site, owned);
            }
            WellKnown::ApiCatalog => self.ingest_catalog(body, site, owned),
        }
    }

    fn ingest_auth(&mut self, wk: WellKnown, body: &str, served: &Url, site: &str, owned: bool) {
        self.ingest_auth_as(wk, body, served, site, owned, None);
    }

    /// Shared body of the auth legs and the declared-server follow-ups.
    /// `declared` = `(resource, issuer)` when this document was followed from a
    /// protected resource's `authorization_servers`: then the validated issuer
    /// must also BE the one declared — a server that answers for some other
    /// issuer (a redirect to a different tenant, a misconfiguration) is not the
    /// one the resource trusts, and is not used.
    fn ingest_auth_as(
        &mut self,
        wk: WellKnown,
        body: &str,
        served: &Url,
        site: &str,
        owned: bool,
        declared: Option<(&str, &str)>,
    ) {
        let Ok(meta) = serde_json::from_str::<AuthMetadata>(body) else {
            return;
        };
        let Some(issuer) = validated(wk, meta.issuer.as_deref(), served)
            .filter(|iss| declared.is_none_or(|(_, want)| iss == want))
        else {
            // Not metadata at all (no issuer), or metadata for some other
            // identifier: MUST NOT be used (RFC 8414 §3.3, OIDC Discovery §4.3).
            self.rejected += usize::from(meta.issuer.is_some());
            return;
        };
        let entry = self.issuers.entry(issuer).or_default();
        if let Some((resource, _)) = declared {
            entry.declared_by.insert(resource.to_string());
        }
        entry.sources.insert(wk.path());
        // Order-independent: an owned serving outranks a delegated one.
        if entry.served_from.is_empty() || (owned && !entry.owned) {
            entry.served_from = served.to_string();
        }
        entry.owned |= owned;
        if owned {
            entry
                .scopes
                .extend(meta.scopes_supported.iter().map(|s| s.trim().to_string()));
            entry.grants.extend(
                meta.grant_types_supported
                    .iter()
                    .map(|s| s.trim().to_string()),
            );
            for url in meta.endpoint_urls() {
                self.add_pivot(url, site);
            }
            for (url, relation) in meta.reference_urls() {
                self.add_reference(url, relation, site, owned);
            }
        }
    }

    fn ingest_resource(&mut self, body: &str, served: &Url, site: &str, owned: bool) {
        let Ok(meta) = serde_json::from_str::<ResourceMetadata>(body) else {
            return;
        };
        let Some(resource) = validated(
            WellKnown::OAuthProtectedResource,
            meta.resource.as_deref(),
            served,
        ) else {
            self.rejected += usize::from(meta.resource.is_some());
            return;
        };
        // A protected resource reached through a cross-site redirect is some
        // other party's API; nothing in it describes this domain.
        if !owned {
            self.rejected += 1;
            return;
        }
        let servers: BTreeSet<String> = meta
            .authorization_servers
            .iter()
            .filter_map(|s| canonical_identifier(s))
            .collect();
        let entry = self.resources.entry(resource).or_default();
        entry.served_from = served.to_string();
        if let Some(name) = meta.resource_name.as_deref().map(str::trim)
            && !name.is_empty()
        {
            entry.name = Some(name.to_string());
        }
        entry
            .scopes
            .extend(meta.scopes_supported.iter().map(|s| s.trim().to_string()));
        entry.authorization_servers.extend(servers.iter().cloned());

        // Each trusted authorization server's host is a pivot: the engine then
        // reads THAT host's own metadata and validates it there.
        for server in servers.iter().chain(meta.jwks_uri.iter()) {
            self.add_pivot(server, site);
        }
        for (url, relation) in meta.reference_urls() {
            self.add_reference(url, relation, site, owned);
        }
    }

    /// The metadata URLs of every declared authorization server whose issuer
    /// carries a PATH (`https://access.stripe.com/mcp`,
    /// `https://auth.atlassian.com/<tenant>`) and is not already validated.
    ///
    /// Such an issuer's metadata lives at a path-derived URL — RFC 8414 §3.1
    /// inserts the well-known between host and path, OIDC Discovery §4 appends
    /// it — so the engine's bare-Domain pivot to its host can never reach it:
    /// the chain dead-ends at the host's apex. This is the one place that still
    /// holds the path. A path-less issuer on another host needs no follow-up —
    /// the pivot to its host reads and validates it there.
    fn declared_metadata_urls(&self) -> Vec<FollowUp> {
        let mut seen = BTreeSet::new();
        let mut out = Vec::new();
        for (resource, facts) in &self.resources {
            for issuer in &facts.authorization_servers {
                if self.issuers.contains_key(issuer)
                    || seen.len() == MAX_DECLARED_SERVERS && !seen.contains(issuer)
                {
                    continue;
                }
                let Some(u) = public_https_url(issuer) else {
                    continue;
                };
                let path = u.path().trim_end_matches('/');
                if path.is_empty() || !seen.insert(issuer.clone()) {
                    continue;
                }
                let origin = u.origin().ascii_serialization();
                for (wk, url) in [
                    (
                        WellKnown::OAuthAuthorizationServer,
                        format!(
                            "{origin}{}{path}",
                            WellKnown::OAuthAuthorizationServer.path()
                        ),
                    ),
                    (
                        WellKnown::OpenIdConfiguration,
                        format!("{origin}{path}{}", WellKnown::OpenIdConfiguration.path()),
                    ),
                ] {
                    out.push(FollowUp {
                        resource: resource.clone(),
                        issuer: issuer.clone(),
                        wk,
                        url,
                    });
                }
            }
        }
        out
    }

    /// Fold in one followed declared-server document (see
    /// [`Self::declared_metadata_urls`]). Validated like any auth document, and
    /// additionally required to be the issuer that was declared.
    fn ingest_declared(&mut self, follow: &FollowUp, body: &str, served: &Url, site: &str) {
        let owned = served_by(served, site);
        self.ingest_auth_as(
            follow.wk,
            body,
            served,
            site,
            owned,
            Some((&follow.resource, &follow.issuer)),
        );
    }

    fn ingest_catalog(&mut self, body: &str, site: &str, owned: bool) {
        for (url, relation) in catalog_links(body) {
            self.add_reference(&url, relation, site, owned);
        }
    }

    /// Record an API reference URL; its host becomes a pivot when owned.
    fn add_reference(&mut self, url: &str, relation: &'static str, site: &str, owned: bool) {
        let Some(u) = public_https_url(url) else {
            return;
        };
        if owned {
            self.add_pivot_host(&u, site);
        }
        self.references.entry(u.to_string()).or_insert(relation);
    }

    /// Add the host of a discovered URL as a pivot when it is a genuine external
    /// one: `https`, a public registrable DNS name (never an IP literal or a
    /// private / special-use name — see [`public_https_url`]), and not the
    /// queried domain itself, which the engine already scanned.
    fn add_pivot(&mut self, url: &str, site: &str) {
        if let Some(u) = public_https_url(url) {
            self.add_pivot_host(&u, site);
        }
    }

    /// Keyed on the engine's canonical Domain form, so the self-pivot check and
    /// the dedup agree with the entity the host becomes: `Entity::new` strips a
    /// leading `www.`, and a raw `www.<site>` endpoint compared by string would
    /// pass the `!= site` check and then be born AS the target — the queried
    /// domain echoed back as its own "discovered" pivot.
    fn add_pivot_host(&mut self, u: &Url, site: &str) {
        if let Some(url::Host::Domain(host)) = u.host() {
            let host = canonical_host(host);
            if host != site {
                self.pivot_hosts.insert(host);
            }
        }
    }

    /// Emit the collection as entities.
    fn emit(&self, domain: &str, scan_id: &str, result: &mut ModuleResult) {
        for (issuer, facts) in &self.issuers {
            let mut e = Entity::new(
                EntityKind::Other("oauth-issuer".into()),
                issuer,
                confidence::HIGH_PLUSPLUS,
                scan_id,
            );
            e.tag("api-discovery");
            e.tag("oauth-issuer");
            let summary = if !facts.declared_by.is_empty() && !facts.owned {
                format!(
                    "Authorization server `{issuer}` declared by {}",
                    joined(&facts.declared_by)
                )
            } else if !facts.owned {
                format!("{domain} delegates OAuth/OIDC discovery to issuer `{issuer}`")
            } else {
                format!("OAuth/OIDC issuer `{issuer}` published by {domain}")
            };
            let mut ev = Evidence::new(SRC, summary)
                .with_attr("issuer", issuer)
                .with_attr("domain", domain)
                .with_attr("served_from", &facts.served_from)
                .with_attr("well_known", joined(&facts.sources))
                .with_attr("validated", "issuer matches its well-known URL");
            if !facts.declared_by.is_empty() {
                e.tag("declared-authorization-server");
                ev = ev.with_attr("declared_by", joined(&facts.declared_by));
            } else if !facts.owned {
                e.tag("delegated-discovery");
                ev = ev.with_attr("delegated", "true");
            }
            if !facts.scopes.is_empty() {
                ev = ev.with_attr("scopes_supported", joined(&facts.scopes));
            }
            if !facts.grants.is_empty() {
                ev = ev.with_attr("grant_types_supported", joined(&facts.grants));
            }
            e.add_evidence(ev);
            result.push(e);
        }

        for (resource, facts) in &self.resources {
            let mut e = Entity::new(
                EntityKind::Other("oauth-protected-resource".into()),
                resource,
                confidence::HIGH_PLUSPLUS,
                scan_id,
            );
            e.tag("api-discovery");
            e.tag("oauth-protected-resource");
            let label = facts.name.as_deref().unwrap_or(resource);
            let mut ev = Evidence::new(
                SRC,
                format!("OAuth-protected API `{label}` published by {domain}"),
            )
            .with_attr("resource", resource)
            .with_attr("domain", domain)
            .with_attr("served_from", &facts.served_from)
            .with_attr("well_known", WellKnown::OAuthProtectedResource.path())
            .with_attr("validated", "resource matches its well-known URL");
            if let Some(name) = &facts.name {
                ev = ev.with_attr("resource_name", name);
            }
            if !facts.authorization_servers.is_empty() {
                ev = ev.with_attr(
                    "authorization_servers",
                    joined(&facts.authorization_servers),
                );
            }
            if !facts.scopes.is_empty() {
                ev = ev.with_attr("scopes_supported", joined(&facts.scopes));
            }
            e.add_evidence(ev);
            result.push(e);
        }

        // Every distinct external endpoint/API host the owner published — an
        // authoritative, dispatchable infrastructure pivot — up to the cap.
        for host in self.pivot_hosts.iter().take(MAX_PIVOT_HOSTS) {
            let mut e = Entity::new(EntityKind::Domain, host, confidence::HIGH, scan_id);
            e.tag("api-discovery");
            e.tag("api-endpoint");
            e.add_evidence(
                Evidence::new(
                    SRC,
                    format!("API/auth endpoint host `{host}` published by {domain}"),
                )
                .with_attr("endpoint_host", host)
                .with_attr("published_by", domain),
            );
            result.push(e);
        }

        // Every distinct API reference — a terminal record of where the org
        // exposes or documents its programmable surface — up to the cap.
        for (url, relation) in self.references.iter().take(MAX_REFERENCES) {
            let mut e = Entity::new(
                EntityKind::Other("api-reference".into()),
                url,
                confidence::STRONG,
                scan_id,
            );
            e.tag("api-discovery");
            e.tag("api-reference");
            e.add_evidence(
                Evidence::new(SRC, format!("API reference `{url}` published by {domain}"))
                    .with_attr("url", url)
                    .with_attr("relation", *relation)
                    .with_attr("domain", domain),
            );
            result.push(e);
        }

        let total = self.pivot_hosts.len() + self.references.len();
        let emitted =
            self.pivot_hosts.len().min(MAX_PIVOT_HOSTS) + self.references.len().min(MAX_REFERENCES);
        if emitted < total {
            result.mark_truncated(
                emitted,
                Some(total),
                &format!(
                    "the per-target caps of {MAX_PIVOT_HOSTS} endpoint hosts and \
                     {MAX_REFERENCES} API references"
                ),
            );
        }
    }
}

#[async_trait]
impl Module for ApiDiscovery {
    fn name(&self) -> &'static str {
        "api_discovery"
    }

    fn description(&self) -> &'static str {
        "Domain-to-API-surface discovery — pivots a domain via its OIDC, OAuth (RFC 8414/9728) and API-catalog (RFC 9727) well-knowns to its validated OAuth issuer, protected APIs (incl. MCP servers), endpoint hosts and API references"
    }

    fn priority(&self) -> u8 {
        90
    }

    fn accepts(&self, t: &Target) -> bool {
        // Kind-only so the dispatch index stays consistent.
        matches!(t.kind, TargetKind::Domain)
    }

    fn category(&self) -> ModuleCategory {
        // Fetches discovery well-knowns from the target's own site (T1594); the
        // issuer, endpoint hosts and API references identify infrastructure the
        // org publishes (T1592.002) — the Web category's default mapping.
        ModuleCategory::Web
    }

    fn produces(&self) -> &'static [EntityKind] {
        // Also emits `Other("oauth-issuer" | "oauth-protected-resource" |
        // "api-reference")`, which cannot live in a `const` slice; the
        // dispatchable pivot is the endpoint/API host Domain.
        const KINDS: &[EntityKind] = &[EntityKind::Domain];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        12_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let domain = target
            .value
            .trim()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        // Light guard — a registrable host with no scheme/path/space.
        if domain.is_empty()
            || domain.len() > 253
            || !domain.contains('.')
            || domain.contains('/')
            || domain.contains(char::is_whitespace)
        {
            return Ok(ModuleResult::new());
        }

        let url = |wk: WellKnown| format!("https://{domain}{}", wk.path());
        let [oidc, oauth, resource, catalog] = WellKnown::ALL.map(url);
        // The four well-knowns are independent — fetch concurrently.
        let (a, b, c, d) = tokio::join!(
            fetch_text(ctx, &oidc),
            fetch_text(ctx, &oauth),
            fetch_text(ctx, &resource),
            fetch_text(ctx, &catalog),
        );
        let mut collected = collect(&domain, WellKnown::ALL.into_iter().zip([a, b, c, d]));

        // Second stage: follow each path-bearing authorization server a
        // protected resource declared to its own spec-derived metadata URL.
        // Best-effort by design — the site was already reached (or not) in the
        // first stage, so a follow-up that fails changes no outage verdict; it
        // only leaves that server recorded as declared-but-unvalidated.
        let follow = collected.found.declared_metadata_urls();
        let fetched =
            futures::future::join_all(follow.iter().map(|f| fetch_text(ctx, &f.url))).await;
        for (f, outcome) in follow.iter().zip(fetched) {
            if let FetchOutcome::Body { body, served } = outcome {
                collected.follow_up(f, &body, &served);
            }
        }
        collected.finish(&domain, &ctx.scan_id)
    }
}

/// The first stage's reduction: everything the four legs found, plus how many
/// were PREVENTED from answering (and the first typed wall among them).
struct Collected {
    /// The target in the engine's canonical Domain form ([`canonical_host`]).
    site: String,
    found: Discovery,
    prevented: usize,
    wall: Option<Error>,
}

/// Fold the four legs' outcomes for `domain` into a [`Collected`]. A leg is
/// *prevented* by a transport failure or a wall; either way the site never said
/// whether it publishes that document.
fn collect(
    domain: &str,
    outcomes: impl IntoIterator<Item = (WellKnown, FetchOutcome)>,
) -> Collected {
    let mut c = Collected {
        site: canonical_host(domain),
        found: Discovery::default(),
        prevented: 0,
        wall: None,
    };
    for (wk, outcome) in outcomes {
        match outcome {
            FetchOutcome::Body { body, served } => c.found.ingest(wk, &body, &served, &c.site),
            FetchOutcome::Answered => {}
            FetchOutcome::Failed => c.prevented += 1,
            FetchOutcome::Blocked(e) => {
                c.prevented += 1;
                c.wall.get_or_insert(e);
            }
        }
    }
    c
}

impl Collected {
    /// Fold in one followed declared-server document (the second stage).
    fn follow_up(&mut self, follow: &FollowUp, body: &str, served: &Url) {
        self.found.ingest_declared(follow, body, served, &self.site);
    }

    /// The module's answer: the collected findings, or an error when EVERY leg
    /// was prevented and nothing was found.
    ///
    /// Only then is the answer an outage rather than the ordinary "publishes no
    /// discovery document" clean miss — a site that answered even one
    /// well-known has demonstrably been reached, so its genuine 404s on the
    /// others still support the negative. A typed wall is preferred over the
    /// generic outage message: it names what actually happened. Pure, so the
    /// whole decision is pinned without a network. (REQ-APIDISCOVERY-001.)
    fn finish(self, domain: &str, scan_id: &str) -> Result<ModuleResult> {
        if self.found.rejected > 0 {
            tracing::debug!(
                module = SRC,
                domain = %domain,
                rejected = self.found.rejected,
                "discovery document(s) failed their spec's identifier check — not used"
            );
        }
        let mut result = ModuleResult::new();
        self.found.emit(domain, scan_id, &mut result);
        if self.prevented == WellKnown::ALL.len() && result.entities.is_empty() {
            return Err(self.wall.unwrap_or_else(|| {
                Error::module(
                    SRC,
                    format!(
                        "every API-discovery well-known failed to answer (transport failure or \
                         server error) for \
                         {domain} — cannot determine whether it publishes a discovery document"
                    ),
                )
            }));
        }
        Ok(result)
    }
}

/// The first stage alone, [`collect`] then [`Collected::finish`] — the whole
/// outcome decision without the network-bound follow-up stage.
#[cfg(test)]
fn conclude(
    domain: &str,
    scan_id: &str,
    outcomes: impl IntoIterator<Item = (WellKnown, FetchOutcome)>,
) -> Result<ModuleResult> {
    collect(domain, outcomes).finish(domain, scan_id)
}

/// Outcome of fetching one discovery well-known: a non-empty 2xx body with the
/// URL that actually served it, a genuine "answered, nothing here" (a 404/410 or
/// plain 4xx, or a 2xx with an unreadable/empty body — an ordinary site's
/// expected negative), a failure to answer (transport or 5xx), or a typed wall
/// (a throttle or an anti-bot page, at any status). Kept distinct so
/// [`Module::process`] can tell a real outage on EVERY well-known apart from the
/// ordinary "this domain publishes no discovery document" clean miss.
enum FetchOutcome {
    Body {
        body: String,
        served: Url,
    },
    Answered,
    /// The site failed to answer: a transport failure, or a 5xx.
    Failed,
    /// The edge refused to serve the well-known — an anti-bot / WAF challenge
    /// page or a rate limit, already typed by [`read_text`]'s shared
    /// `document_or_challenge`. Distinct from `Answered` because the site did
    /// NOT tell us it publishes no discovery document; it told us nothing.
    Blocked(Error),
}

/// Text GET classified into a [`FetchOutcome`]. A `send()` failure or a 5xx is
/// `Failed`; a 429 or an anti-bot page (at any status) is `Blocked`, typed; a
/// 404/410, a plain 4xx and an unreadable/empty 2xx body stay `Answered` (an
/// ordinary domain 404s on every well-known — that must never read as an
/// outage). A 2xx wall stays `Blocked` too, never folded into the ordinary
/// negative — the discarded-typed-error shape `app_links` had to fix
/// (REQ-APPLINKS-001).
async fn fetch_text(ctx: &ModuleContext, url: &str) -> FetchOutcome {
    let resp = match ctx.http.get(url).send_tagged(SRC).await {
        Ok(r) => r,
        Err(_) => return FetchOutcome::Failed,
    };
    let status = resp.status();
    if !status.is_success() {
        // 404 / 410: the ordinary "not published here", with no body to read.
        if matches!(status.as_u16(), 404 | 410) {
            return FetchOutcome::Answered;
        }
        // Everything else through the shared classifier, so a throttle and a
        // wall keep their type — the collapse `util::http::ok_or_absent` exists
        // to prevent ("folds a 403 scraper block, a 429 throttle and a 5xx
        // outage into the same answer as a genuine miss"). A bare
        // `!is_success() → Answered` made four 429s read as a site that
        // publishes nothing, and left the `RateLimited` arm below unreachable.
        return match http_status_error(SRC, resp).await {
            e @ (Error::RateLimited(_) | Error::BotChallenge(_)) => FetchOutcome::Blocked(e),
            _ if status.is_server_error() => FetchOutcome::Failed,
            // A plain 4xx (401, 403, 405 …) is the site's answer: this document
            // is not public here. Deliberately not an outage — a stock
            // "deny dotfiles" rule 403s every `/.well-known/` path, and reading
            // that as a failure would error on ordinary sites by the thousand.
            _ => FetchOutcome::Answered,
        };
    }
    // Captured before the body stream consumes `resp`: the spec checks are
    // against the URL that answered, which a redirect may have changed.
    let served = resp.url().clone();
    match read_text(SRC, resp).await {
        Ok(body) if !body.trim().is_empty() => FetchOutcome::Body { body, served },
        // An empty 2xx really is the ordinary negative.
        Ok(_) => FetchOutcome::Answered,
        // A WALL is not an answer — `read_text` types a 2xx anti-bot / WAF page
        // as `BotChallenge` and a throttle as `RateLimited`.
        Err(e) if matches!(e, Error::BotChallenge(_) | Error::RateLimited(_)) => {
            FetchOutcome::Blocked(e)
        }
        // An unreadable body stays the ordinary negative.
        Err(_) => FetchOutcome::Answered,
    }
}

/// The document's declared identifier, canonicalised, when it is exactly the
/// identifier its serving URL requires; else `None` (the document MUST NOT be
/// used).
fn validated(wk: WellKnown, declared: Option<&str>, served: &Url) -> Option<String> {
    let declared = canonical_identifier(declared?)?;
    (wk.expected_identifier(served)? == declared).then_some(declared)
}

/// Canonical form of an OAuth identifier (issuer / resource / authorization
/// server): an `https` URL with no query, fragment or userinfo (RFC 8414 §2,
/// RFC 9728 §2), serialised as origin + path with a trailing `/` removed, so
/// `https://h`, `https://h/` and `https://H:443` compare equal while
/// `https://h/tenant` stays distinct.
fn canonical_identifier(raw: &str) -> Option<String> {
    let u = Url::parse(raw.trim()).ok()?;
    if u.scheme() != "https"
        || u.query().is_some()
        || u.fragment().is_some()
        || !u.username().is_empty()
        || u.password().is_some()
        || u.host().is_none()
    {
        return None;
    }
    Some(format!(
        "{}{}",
        u.origin().ascii_serialization(),
        u.path().trim_end_matches('/')
    ))
}

/// `raw` parsed when it is an `https` URL with no userinfo whose host is a
/// public, registrable DNS name; `None` for anything else — another scheme, an IP
/// literal (the WHATWG parser canonicalises `2130706433` / `0x7f000001` to
/// `127.0.0.1`, so numeric encodings cannot slip past), a single-label name, or
/// a private / special-use name refused by the shared SSRF preflight
/// ([`url_host_is_private`], the same authority the engine's dispatch gate
/// uses). A hostile discovery document listing `http://169.254.169.254/` or
/// `https://db.internal/` as an endpoint therefore mints nothing.
fn public_https_url(raw: &str) -> Option<Url> {
    let u = Url::parse(raw.trim()).ok()?;
    // Userinfo is refused like any other disqualifier, the same rule
    // `canonical_identifier` applies to issuers: every accepted URL is
    // persisted verbatim as an entity value, and `https://user:secret@host/`
    // in a document the target controls would copy its credential into the
    // scan's findings.
    if u.scheme() != "https"
        || !u.username().is_empty()
        || u.password().is_some()
        || url_host_is_private(u.as_str())
    {
        return None;
    }
    match u.host() {
        Some(url::Host::Domain(h)) if h.contains('.') => Some(u),
        _ => None,
    }
}

/// Every `(href, relation)` an API catalog publishes under one of the
/// [`CATALOG_RELATIONS`], plus each per-API `anchor` (RFC 9727 §4 anchors a
/// context at the API it describes). Reads the RFC 9264 JSON form, and falls
/// back to the `application/linkset` text form (`<uri>; rel="item", …`).
fn catalog_links(body: &str) -> Vec<(String, &'static str)> {
    let mut out = Vec::new();
    if let Ok(set) = serde_json::from_str::<Linkset>(body) {
        for ctx in &set.linkset {
            if let Some(anchor) = ctx.anchor.as_deref()
                && !anchor.contains("/.well-known/api-catalog")
            {
                out.push((anchor.to_string(), "anchor"));
            }
            let groups: [(&'static str, &Vec<LinkTarget>); 4] = [
                ("item", &ctx.item),
                ("service-desc", &ctx.service_desc),
                ("service-doc", &ctx.service_doc),
                ("service-meta", &ctx.service_meta),
            ];
            for (rel, targets) in groups {
                out.extend(
                    targets
                        .iter()
                        .filter_map(|t| t.href.clone())
                        .map(|h| (h, rel)),
                );
            }
        }
        return out;
    }
    // Text form: each link value is `<target>` followed by `;`-separated
    // parameters, values separated by commas. Only `<https://…>` targets with a
    // known relation are read, so an HTML page (which never has that shape)
    // yields nothing.
    let mut rest = body;
    while let Some(open) = rest.find("<https://") {
        let after = &rest[open + 1..];
        let Some(close) = after.find('>') else {
            break;
        };
        let target = &after[..close];
        let params_end = after[close..].find('<').map_or(after.len(), |i| close + i);
        let params = &after[close + 1..params_end];
        for rel in link_rels(params) {
            if let Some(known) = CATALOG_RELATIONS.iter().find(|r| **r == rel) {
                out.push((target.to_string(), *known));
            }
        }
        rest = &after[params_end..];
    }
    out
}

/// The relation types in one link value's parameters (`; rel="item service-doc"`
/// or unquoted `; rel=item`).
fn link_rels(params: &str) -> Vec<String> {
    params
        .split(';')
        .filter_map(|p| {
            let (k, v) = p.split_once('=')?;
            k.trim()
                .eq_ignore_ascii_case("rel")
                .then(|| v.trim().trim_end_matches(',').trim().trim_matches('"'))
        })
        .flat_map(|v| v.split_ascii_whitespace())
        .map(str::to_ascii_lowercase)
        .collect()
}

/// True when `served` — the URL that actually answered — is the site itself or
/// a host under it, compared in canonical form so `www.x` ↔ `x` and the
/// absolute `x.` stay the owner's. The one ownership authority: a document is
/// the site's own only when this holds, and only then are its endpoint hosts
/// pivots.
fn served_by(served: &Url, site: &str) -> bool {
    served
        .host_str()
        .is_some_and(|h| is_or_subdomain_of(&canonical_host(h), site))
}

/// A host in the engine's canonical Domain form — the one authority
/// (`core::entity::normalise`) every Domain entity is born through.
fn canonical_host(host: &str) -> String {
    crate::core::entity::normalise(&EntityKind::Domain, host)
}

fn joined<S: AsRef<str>>(set: &BTreeSet<S>) -> String {
    set.iter().map(AsRef::as_ref).collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
