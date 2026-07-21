//! Fediverse / Mastodon account discovery via WebFinger. Free, no API key.
//!
//! A Fediverse handle (`user@instance`) is **syntactically an email**, so any
//! email-shaped identifier can be probed with the standard WebFinger discovery
//! request:
//!
//! `GET https://<domain>/.well-known/webfinger?resource=acct:<user>@<domain>`
//!
//! A regular mail domain returns `404` (it runs no WebFinger server); a
//! Fediverse instance returns the account's real profile — the human profile
//! page, the ActivityPub actor URL, and the local username. So this turns an
//! email into a decentralized-social footprint check: "does this identifier
//! have a Mastodon/Pleroma/Misskey presence, and where?" — a growing
//! post-Twitter surface that the keyed OSINT stacks miss. No mock: the JSON is
//! fetched live from the instance's own discovery endpoint.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::extract::looks_like_email;
use crate::util::http::{fetch_json_probe, urlencode};

const SRC: &str = "fediverse";

pub struct Fediverse;

#[derive(Deserialize, Default)]
#[serde(default)]
struct WebFinger {
    aliases: Vec<String>,
    links: Vec<Link>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Link {
    rel: Option<String>,
    #[serde(rename = "type")]
    typ: Option<String>,
    href: Option<String>,
}

#[async_trait]
impl Module for Fediverse {
    fn name(&self) -> &'static str {
        "fediverse"
    }

    fn description(&self) -> &'static str {
        "Fediverse/Mastodon account discovery — resolves an email-shaped handle to its profile via WebFinger"
    }

    fn priority(&self) -> u8 {
        104
    }

    fn accepts(&self, t: &Target) -> bool {
        // Kind-only so the dispatch index stays consistent; the email-shape gate
        // is applied in process().
        matches!(t.kind, TargetKind::Email)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Social
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Username, EntityKind::Url, EntityKind::Email];
        KINDS
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Social default carries T1589.003 (Employee Names), but this module
        // searches the fediverse for a handle and emits a `Username`/`Url` plus any
        // profile `Email` — never a real-name `Person` — so T1589.003 is
        // over-claimed. The account search is T1593.001 (Social Media) and the
        // profile email is T1589.002 (Email Addresses); same shape as nostr /
        // hacker_news / reddit_user.
        &["T1589.002", "T1593.001"]
    }

    fn max_timeout_ms(&self) -> u64 {
        8_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();
        let email = target.value.trim();
        if !looks_like_email(email) {
            return Ok(result);
        }
        let Some((_, domain)) = email.split_once('@') else {
            return Ok(result);
        };
        // A freemail provider (gmail/outlook/yahoo/…) runs no WebFinger server, so
        // the probe is a CERTAIN 404 — skip it rather than spend an 8 s request on a
        // guaranteed miss (freemail is the majority of email seeds, so this removes
        // most of the module's wasted-request load on a metered Termux radio).
        if !domain_worth_probing(domain) {
            return Ok(result);
        }

        let url = format!(
            "https://{domain}/.well-known/webfinger?resource={}",
            urlencode(&format!("acct:{email}"))
        );
        // 404 (the overwhelming case for ordinary mail domains) → not a Fediverse
        // account, a clean miss. A domain that is simply unreachable (runs no
        // server, DNS/TLS/connection failure) is the SAME "no account here" miss,
        // not a module error — `fetch_json_probe` folds both into `None`.
        let Some(wf): Option<WebFinger> = fetch_json_probe(&ctx.http, SRC, &url).await else {
            return Ok(result);
        };
        if wf.links.is_empty() && wf.aliases.is_empty() {
            return Ok(result);
        }

        extract_webfinger(&wf, email, domain, &ctx.scan_id, &mut result);
        Ok(result)
    }
}

/// Whether `domain` is worth a WebFinger probe. A freemail provider never runs a
/// WebFinger server, so the probe is a guaranteed 404 and is skipped; a custom
/// domain MIGHT be a self-hosted Fediverse instance (people run Mastodon/Pleroma
/// on their own domain), so it is still probed. Pure.
fn domain_worth_probing(domain: &str) -> bool {
    !crate::util::domains::is_freemail(domain)
}

/// Build entities from a resolved WebFinger document. Pure (no I/O) so it is
/// unit-tested against a fixture; the network shell in `process` stays thin.
fn extract_webfinger(
    wf: &WebFinger,
    email: &str,
    domain: &str,
    scan_id: &str,
    result: &mut ModuleResult,
) {
    let local = email.split('@').next().unwrap_or(email);
    let ev = Evidence::new(SRC, format!("Fediverse account `{email}` (WebFinger)"))
        .with_attr("handle", email)
        .with_attr("instance", domain)
        .with_attr("source", "webfinger");

    // The human profile page (rel=profile-page) and the ActivityPub actor
    // (rel=self, activity+json). Both are first-class URL pivots.
    let profile_page = wf
        .links
        .iter()
        .find(|l| l.rel.as_deref() == Some("http://webfinger.net/rel/profile-page"))
        .and_then(|l| l.href.as_deref());
    let actor = wf
        .links
        .iter()
        .find(|l| {
            l.rel.as_deref() == Some("self")
                && l.typ
                    .as_deref()
                    .is_some_and(|t| t.contains("activity+json"))
        })
        .and_then(|l| l.href.as_deref());

    for (href, conf) in [(profile_page, 0.82), (actor, 0.76)] {
        if let Some(u) = href.filter(|u| u.starts_with("http")) {
            let mut url_e = Entity::new(EntityKind::Url, u, conf, scan_id);
            url_e.tag("fediverse");
            url_e.tag("mastodon");
            url_e.tag("social-profile");
            url_e.add_evidence(ev.clone());
            result.push(url_e);
        }
    }

    // `aliases` are additional self-referential URIs WebFinger asserts for the
    // same subject — sibling data to the typed `rel` links above, but untyped
    // (no `rel`/`type` to confirm which is the profile page vs. the actor), so
    // each is still a URL pivot, just at a confidence below the typed
    // actor/profile-page tiers.
    for alias in wf.aliases.iter().filter(|a| a.starts_with("http")) {
        let mut url_e = Entity::new(
            EntityKind::Url,
            alias.as_str(),
            confidence::HIGH_PLUS,
            scan_id,
        );
        url_e.tag("fediverse");
        url_e.tag("mastodon");
        url_e.tag("webfinger-alias");
        url_e.add_evidence(ev.clone());
        result.push(url_e);
    }

    // The local username — a pivot into the free username stack.
    if local.len() >= 2 {
        let mut u = Entity::new(EntityKind::Username, local, 0.68, scan_id);
        u.tag("fediverse");
        u.tag("mastodon");
        u.add_evidence(ev.clone());
        result.push(u);
    }

    // Flag the seed email itself as a confirmed Fediverse identity (GREATEST-
    // merge only ever adds the tag/evidence, never lowers existing confidence).
    let mut seed = Entity::new(EntityKind::Email, email, 0.78, scan_id);
    seed.tag("fediverse");
    seed.add_evidence(ev);
    result.push(seed);
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
