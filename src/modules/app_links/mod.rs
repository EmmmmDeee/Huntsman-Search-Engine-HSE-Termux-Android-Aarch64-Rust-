//! Domain → mobile-app attribution from the two public app-linkage
//! well-knowns. Free, no API key.
//!
//! Native apps that deep-link a website must prove the association in files the
//! **domain owner publishes**, so reading them attributes a domain to its
//! official apps and the developer identities behind them:
//!
//! * **Android — Digital Asset Links**
//!   `GET https://<domain>/.well-known/assetlinks.json` — an array of
//!   statements. An `android_app` target yields the app's `package_name` and
//!   the SHA-256 fingerprints of its **signing certificate** (a strong
//!   developer-identity fingerprint); a `web` target yields a *delegated*
//!   sibling domain the same owner controls.
//! * **iOS — Apple App Site Association (AASA)**
//!   `GET https://<domain>/.well-known/apple-app-site-association` — each
//!   `appID` is `<TeamID>.<BundleID>`, so it exposes the **Apple Developer
//!   Team ID** (the organisation's stable developer identifier) and the app's
//!   bundle ID.
//!
//! Together they map a domain to its mobile footprint and the org/signing
//! identities that publish it — a pivot the keyed OSINT stacks don't surface.
//! An ordinary site simply 404s on both (a clean miss). No mock: the JSON is
//! fetched live from the domain's own well-known path.

use std::collections::BTreeSet;

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::{RequestBuilderExt, read_text};

const SRC: &str = "app_links";

pub struct AppLinks;

/// One Android Digital Asset Links statement.
#[derive(Deserialize, Default)]
#[serde(default)]
struct AssetStatement {
    target: AssetTarget,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct AssetTarget {
    namespace: Option<String>,
    package_name: Option<String>,
    sha256_cert_fingerprints: Vec<String>,
    site: Option<String>,
}

/// The Apple App Site Association document (only the app-identity fields).
#[derive(Deserialize, Default)]
#[serde(default)]
struct Aasa {
    applinks: AppLinksBlock,
    webcredentials: AppList,
    appclips: AppList,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct AppLinksBlock {
    details: Vec<AppDetail>,
    apps: Vec<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct AppDetail {
    #[serde(rename = "appID")]
    app_id: Option<String>,
    #[serde(rename = "appIDs")]
    app_ids: Vec<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct AppList {
    apps: Vec<String>,
}

#[async_trait]
impl Module for AppLinks {
    fn name(&self) -> &'static str {
        "app_links"
    }

    fn description(&self) -> &'static str {
        "Domain-to-mobile-app attribution — pivots a domain via app-linkage well-knowns to Android package + signing cert, Apple Team ID + bundle, and delegated domains"
    }

    fn priority(&self) -> u8 {
        90
    }

    fn accepts(&self, t: &Target) -> bool {
        // Kind-only so the dispatch index stays consistent.
        matches!(t.kind, TargetKind::Domain)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Web
    }

    fn produces(&self) -> &'static [EntityKind] {
        // Also emits `Other("android-app-id" | "ios-bundle-id" | "apple-team-id"
        // | "apple-app-id" | "cert-sha256")`, which cannot live in a `const`
        // slice; the dispatchable pivot is the delegated Domain.
        const KINDS: &[EntityKind] = &[EntityKind::Domain];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        12_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();
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
            return Ok(result);
        }

        let android_url = format!("https://{domain}/.well-known/assetlinks.json");
        let ios_url = format!("https://{domain}/.well-known/apple-app-site-association");
        // Both well-knowns are independent — fetch concurrently.
        let (android, ios) =
            tokio::join!(fetch_text(ctx, &android_url), fetch_text(ctx, &ios_url),);

        if let Some(body) = android {
            parse_assetlinks(&body, &domain, &ctx.scan_id, &mut result);
        }
        if let Some(body) = ios {
            parse_aasa(&body, &domain, &ctx.scan_id, &mut result);
        }
        Ok(result)
    }
}

/// Best-effort text GET: a transport error or unreadable body is a clean miss,
/// never a scan error (an ordinary domain 404s on both well-knowns).
async fn fetch_text(ctx: &ModuleContext, url: &str) -> Option<String> {
    let resp = ctx.http.get(url).send_tagged(SRC).await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    read_text(SRC, resp).await.ok().filter(|b| !b.is_empty())
}

/// Parse Android Digital Asset Links: app packages + signing-cert fingerprints,
/// plus delegated sibling domains.
fn parse_assetlinks(body: &str, domain: &str, scan_id: &str, result: &mut ModuleResult) {
    let Ok(statements) = serde_json::from_str::<Vec<AssetStatement>>(body) else {
        return;
    };
    let mut packages = BTreeSet::new();
    let mut fingerprints = BTreeSet::new();
    let mut sites = BTreeSet::new();

    for st in &statements {
        match st.target.namespace.as_deref() {
            Some("android_app") => {
                if let Some(pkg) = st.target.package_name.as_deref().filter(|p| is_pkg(p)) {
                    packages.insert(pkg.to_string());
                }
                for fp in &st.target.sha256_cert_fingerprints {
                    if is_sha256_fp(fp) {
                        fingerprints.insert(fp.to_ascii_uppercase());
                    }
                }
            }
            Some("web") => {
                if let Some(host) = st.target.site.as_deref().and_then(host_of)
                    && host != domain
                {
                    sites.insert(host);
                }
            }
            _ => {}
        }
    }

    // Every distinct app / fingerprint / delegated domain is emitted — no cap.
    // These come from the well-known file the DOMAIN OWNER publishes, so each is
    // an authoritative, owner-asserted attribution: the packages, signing certs,
    // and Apple IDs are terminal `Other` identity records (never re-dispatched),
    // and the delegated `web` domains are siblings the owner PROVES control of
    // (Digital Asset Links), i.e. genuinely-owned pivots — not co-tenant noise.
    // The sets are `BTreeSet`s, so output stays sorted, deduplicated, and
    // deterministic; the expansion frontier for the domains is the engine's ROI
    // gate, not this leaf.
    for pkg in &packages {
        let mut e = Entity::new(
            EntityKind::Other("android-app-id".into()),
            pkg,
            0.80,
            scan_id,
        );
        e.tag("app-links");
        e.tag("android-app");
        e.add_evidence(
            Evidence::new(SRC, format!("Android app `{pkg}` linked from {domain}"))
                .with_attr("package_name", pkg)
                .with_attr("domain", domain)
                .with_attr("source", "assetlinks.json"),
        );
        result.push(e);
    }
    for fp in &fingerprints {
        let mut e = Entity::new(EntityKind::Other("cert-sha256".into()), fp, 0.78, scan_id);
        e.tag("app-links");
        e.tag("signing-cert");
        e.add_evidence(
            Evidence::new(
                SRC,
                format!("Android signing-cert SHA-256 linked from {domain}"),
            )
            .with_attr("sha256_fingerprint", fp)
            .with_attr("domain", domain),
        );
        result.push(e);
    }
    for site in &sites {
        let mut e = Entity::new(EntityKind::Domain, site, 0.65, scan_id);
        e.tag("app-links");
        e.tag("delegated-domain");
        e.add_evidence(
            Evidence::new(
                SRC,
                format!("Domain delegated by {domain} (Digital Asset Links)"),
            )
            .with_attr("delegated_by", domain)
            .with_attr("source", "assetlinks.json"),
        );
        result.push(e);
    }
}

/// Parse the Apple App Site Association: Team IDs + bundle IDs from every
/// `appID` across applinks / webcredentials / appclips.
fn parse_aasa(body: &str, domain: &str, scan_id: &str, result: &mut ModuleResult) {
    let Ok(doc) = serde_json::from_str::<Aasa>(body) else {
        return;
    };
    // Collect every appID form the document exposes.
    let mut app_ids: BTreeSet<String> = BTreeSet::new();
    for d in &doc.applinks.details {
        if let Some(id) = d.app_id.as_deref() {
            app_ids.insert(id.to_string());
        }
        app_ids.extend(d.app_ids.iter().cloned());
    }
    app_ids.extend(doc.applinks.apps.iter().cloned());
    app_ids.extend(doc.webcredentials.apps.iter().cloned());
    app_ids.extend(doc.appclips.apps.iter().cloned());

    // Every appID (and its derived bundle ID + Team ID) is emitted — no cap.
    // Each is an owner-published, terminal `Other` identity record from the AASA
    // file; `app_ids`/`teams` are `BTreeSet`s so the output stays sorted, deduped,
    // and deterministic.
    let mut teams = BTreeSet::new();
    for app_id in &app_ids {
        let Some((team, bundle)) = split_app_id(app_id) else {
            continue;
        };
        // Full app identifier.
        let mut e = Entity::new(
            EntityKind::Other("apple-app-id".into()),
            app_id,
            0.80,
            scan_id,
        );
        e.tag("app-links");
        e.tag("ios-app");
        e.add_evidence(
            Evidence::new(SRC, format!("iOS app `{app_id}` linked from {domain}"))
                .with_attr("app_id", app_id)
                .with_attr("team_id", team)
                .with_attr("bundle_id", bundle)
                .with_attr("domain", domain)
                .with_attr("source", "apple-app-site-association"),
        );
        result.push(e);

        // Bundle ID.
        let mut b = Entity::new(
            EntityKind::Other("ios-bundle-id".into()),
            bundle,
            0.78,
            scan_id,
        );
        b.tag("app-links");
        b.tag("ios-app");
        b.add_evidence(
            Evidence::new(SRC, format!("iOS bundle `{bundle}` linked from {domain}"))
                .with_attr("bundle_id", bundle)
                .with_attr("domain", domain),
        );
        result.push(b);

        // Apple Developer Team ID (deduped — many apps share one team).
        if teams.insert(team.to_string()) {
            let mut t = Entity::new(
                EntityKind::Other("apple-team-id".into()),
                team,
                0.80,
                scan_id,
            );
            t.tag("app-links");
            t.tag("apple-team");
            t.add_evidence(
                Evidence::new(
                    SRC,
                    format!("Apple Developer Team `{team}` (from {domain})"),
                )
                .with_attr("team_id", team)
                .with_attr("domain", domain)
                .with_attr("source", "apple-app-site-association"),
            );
            result.push(t);
        }
    }
}

/// Split `TeamID.BundleID` into its parts when the leading label is a valid
/// 10-char Apple Team ID. `None` otherwise (so a malformed `appID` is skipped).
fn split_app_id(app_id: &str) -> Option<(&str, &str)> {
    let (team, bundle) = app_id.split_once('.')?;
    if is_team_id(team) && !bundle.is_empty() {
        Some((team, bundle))
    } else {
        None
    }
}

/// An Apple Team ID is exactly 10 upper-case-alphanumeric characters.
fn is_team_id(s: &str) -> bool {
    s.len() == 10
        && s.bytes()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
}

/// A plausible Android/iOS reverse-DNS package id: dotted, alphanumeric labels.
fn is_pkg(s: &str) -> bool {
    s.len() >= 3
        && s.len() <= 155
        && s.contains('.')
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'_')
        && !s.starts_with('.')
        && !s.ends_with('.')
}

/// A SHA-256 cert fingerprint: 32 colon-separated hex octets (`AB:CD:…`).
fn is_sha256_fp(s: &str) -> bool {
    let parts: Vec<&str> = s.split(':').collect();
    parts.len() == 32
        && parts
            .iter()
            .all(|p| p.len() == 2 && p.bytes().all(|c| c.is_ascii_hexdigit()))
}

/// Extract the bare host from an asset-link `site` (`https://host[/...]`).
fn host_of(site: &str) -> Option<String> {
    let rest = site
        .strip_prefix("https://")
        .or_else(|| site.strip_prefix("http://"))?;
    let host = rest.split(['/', ':', '?']).next()?.trim();
    (host.contains('.') && !host.contains(char::is_whitespace)).then(|| host.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
