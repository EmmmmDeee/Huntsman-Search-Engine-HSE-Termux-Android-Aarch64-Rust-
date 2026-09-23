//! Cert Spotter — free Certificate Transparency issuance search (SSLMate).
//!
//! Endpoint:
//!   `GET https://api.certspotter.com/v1/issuances
//!        ?domain={host}&include_subdomains=true&expand=dns_names&expand=issuer`
//! Auth: None — the anonymous tier is free and key-less (rate-limited; a 429
//! simply surfaces as a module error and the engine moves on, exactly like any
//! other transient free-source failure).
//!
//! Pagination: the endpoint is a cursor. The API reference says it "returns a
//! limited number of issuances in a single response" and that a client takes
//! the `id` of the last issuance, passes it back as `after=`, and repeats
//! "until the issuances endpoint returns an empty array". One page is not the
//! answer for a busy apex — see [`walk_issuances`] for how far the cursor is
//! followed and how a walk that stops early is reported.
//!
//! This is the deliberate COMPANION to [`crate::modules::crtsh`], not a
//! duplicate: no single Certificate-Transparency aggregator has complete log
//! coverage, so offensive subdomain enumeration standardly queries several
//! (subfinder / amass / assetfinder all do). crt.sh reads its own monitored-log
//! database; Cert Spotter runs an independent monitor with different freshness
//! and back-fill, so each routinely surfaces hostnames the other misses — running
//! both maximises the attack-surface recall from one apex seed. The issuer-org
//! parsing and public-CA suppression are shared with `crtsh` (single source of
//! truth) rather than re-encoded here.

use async_trait::async_trait;
use serde::Deserialize;
use std::collections::HashSet;

use crate::core::confidence;
use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
    tags,
};
use crate::modules::crtsh::{is_public_ca, parse_dn_org};
use crate::util::http::urlencode;

const SRC: &str = "certspotter";

/// The issuances endpoint. [`walk_issuances`] takes the base as an argument so
/// the hermetic tests can point the same walk at a loopback listener.
const ISSUANCES_URL: &str = "https://api.certspotter.com/v1/issuances";

/// Issuances in one full page. **Measured, not documented** (2026-09-22): the
/// reference says only "a limited number"; `google.com` returned exactly 100,
/// `github.com` returned 75 and then the terminating empty array. A page
/// shorter than this is therefore the end of the data, and the cursor is not
/// followed past it — so a small domain costs one request, as it always has,
/// out of an anonymous budget of ten an hour (`x-ratelimit-limit: 10`).
///
/// If SSLMate ever shrinks the page, a short page would be misread as the end;
/// that is the assumption this constant records. Growing it is harmless: a
/// larger page is still `>=` this and still followed.
const PAGE_SIZE: usize = 100;

/// Pages of the `after=` cursor followed for one query. Each page spends one
/// request of the anonymous hourly budget, so the walk is bounded rather than
/// exhaustive; a walk that reaches the cap is reported as truncated, never as
/// complete.
const MAX_PAGES: usize = 5;

/// A further page is only requested while the walk is younger than this. The
/// engine's timeout discards everything a module collected, so a walk that
/// kept paging until it was killed would lose the pages it already had; this
/// stops it early enough that the page in flight can still finish inside
/// [`Module::max_timeout_ms`] (the server itself gives up on a query at
/// 10 s, answering `504 {"code":"timeout",…}`).
const NEXT_PAGE_CUTOFF: std::time::Duration = std::time::Duration::from_secs(10);

/// One issuance object from the `v1/issuances` array, expanded with `dns_names`
/// and `issuer`. Every field is optional so a partial/renamed response degrades
/// to fewer entities rather than a hard deserialize error.
#[derive(Deserialize)]
struct Issuance {
    /// The opaque cursor for the NEXT page: the last issuance's `id` is passed
    /// back as `after=` (see [`walk_issuances`]).
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    dns_names: Vec<String>,
    #[serde(default)]
    issuer: Option<Issuer>,
    #[serde(default)]
    not_before: Option<String>,
    #[serde(default)]
    not_after: Option<String>,
    /// The certificate's SHA-256 — an infrastructure-attribution pivot: the same
    /// cert fingerprint seen across hosts links their certificates / operator
    /// (the Cert Spotter analogue of crt.sh's `serial_number`).
    #[serde(default)]
    cert_sha256: Option<String>,
}

#[derive(Deserialize)]
struct Issuer {
    /// The issuer Distinguished Name, e.g. `"C=US, O=Let's Encrypt, CN=R3"`.
    #[serde(default)]
    name: Option<String>,
}

/// Shared evidence for a CT issuance-derived entity: the issuing CA DN, the
/// validity window, and — when present — the certificate SHA-256 fingerprint
/// pivot. **Pure.**
fn cert_evidence(entry: &Issuance, summary: &str) -> Evidence {
    let issuer = entry
        .issuer
        .as_ref()
        .and_then(|i| i.name.as_deref())
        .unwrap_or("");
    let mut ev = Evidence::new(SRC, summary.to_string())
        .with_attr("issuer", issuer)
        .with_attr("not_before", entry.not_before.as_deref().unwrap_or(""))
        .with_attr("not_after", entry.not_after.as_deref().unwrap_or(""));
    if let Some(fp) = entry.cert_sha256.as_deref().filter(|s| !s.is_empty()) {
        ev = ev.with_attr("cert_sha256", fp);
    }
    ev
}

/// Map Cert Spotter issuances to deduplicated `Domain` / `Organisation`
/// entities. **Pure** (no network/IO): flattens each issuance's `dns_names`,
/// skips wildcards, classifies a name as a subdomain of `domain_base`
/// (case-folded) for a confidence boost, dedups across the whole response, and
/// mines the non-public issuing CA as a high-value attribution pivot. Returns
/// EVERY distinct entity, confidence-descending (uid-tie-broken) — no per-module
/// cap, because each subdomain / enterprise-CA org is a real BFS pivot and the
/// frontier budget is the engine's, not this leaf module's (mirrors `crtsh`).
fn build_entities(entries: &[Issuance], domain_base: &str, scan_id: &str) -> Vec<Entity> {
    // Normalised the same way `Entity::new` normalises every Domain value
    // (canonically strips leading "www." labels — see its doc comment) so a
    // dns_names entry's dedup key and subdomain classification match the
    // identity the entity actually gets constructed under. Mirrors the
    // identical fix in the sibling `crtsh` module.
    let base = crate::core::entity::normalise(
        &EntityKind::Domain,
        domain_base
            .trim()
            .trim_end_matches('.')
            .to_lowercase()
            .as_str(),
    );
    let mut seen_domains: HashSet<String> = HashSet::new();
    let mut seen_issuers: HashSet<String> = HashSet::new();

    let mut out: Vec<Entity> = entries
        .iter()
        .flat_map(|entry| entry.dns_names.iter().map(move |name| (entry, name)))
        .filter_map(|(entry, raw_name)| {
            let name = raw_name.trim().trim_end_matches('.').to_lowercase();
            // Skip blanks, wildcards (`*.example.com` — not a resolvable host),
            // and anything that isn't a dotted hostname.
            if name.is_empty() || name.starts_with('*') || !name.contains('.') {
                return None;
            }
            // De-dup and classify against the SAME normalised identity
            // `Entity::new` will construct below, not the raw dns_names text —
            // otherwise "www.example.com" and "example.com" from the same
            // issuance are two distinct names here (each independently
            // earning its own dedup slot and subdomain verdict) yet both
            // collapse to one uid once constructed. `Entity::merge`'s
            // tag-union then keeps whichever of the two was (correctly, in
            // isolation) tagged SUBDOMAIN, mislabeling the apex regardless of
            // this site's own classification being right for a name
            // considered by itself. Mirrors the identical fix in the sibling
            // `crtsh` module.
            let canonical = crate::core::entity::normalise(&EntityKind::Domain, &name);
            if !seen_domains.insert(canonical.clone()) {
                return None;
            }
            // Proper-subdomain, not `is_or_subdomain_of` — the apex itself
            // routinely appears in its own cert's dns_names (a single cert
            // commonly SANs both "example.com" and "www.example.com"), and
            // the apex is not a subdomain of itself; using the inclusive
            // check mislabeled it `tags::SUBDOMAIN`.
            let is_sub = crate::util::domains::is_proper_subdomain_of(&canonical, &base);
            let conf = if is_sub {
                confidence::VERY_HIGH
            } else {
                confidence::LOW_MEDIUM
            };
            let mut e = Entity::new(EntityKind::Domain, &name, conf, scan_id);
            e.tag(tags::CT_LOG);
            if is_sub {
                e.tag(tags::SUBDOMAIN);
            }
            e.add_evidence(cert_evidence(
                entry,
                "Certificate Transparency issuance (Cert Spotter)",
            ));
            Some(e)
        })
        .collect();

    // Non-public issuing-CA organisations — one per unique O= value. A custom /
    // enterprise CA in the CT log reveals internal PKI and is a strong operator
    // attribution pivot (identical policy to `crtsh`, via the shared helpers).
    out.extend(entries.iter().filter_map(|entry| {
        let dn = entry.issuer.as_ref()?.name.as_deref()?;
        let org = parse_dn_org(dn)?;
        if is_public_ca(org) {
            return None;
        }
        if !seen_issuers.insert(org.to_lowercase()) {
            return None;
        }
        let mut o = Entity::new(
            EntityKind::Organisation,
            org,
            confidence::MEDIUM_HIGH,
            scan_id,
        );
        o.tag(tags::CT_LOG);
        o.tag("certificate-issuer");
        o.tag("derived");
        o.add_evidence(
            cert_evidence(entry, &format!("Certificate issuer organisation: {org}"))
                .with_attr("issuer_dn", dn)
                .with_attr("signed_domain", &base),
        );
        Some(o)
    }));

    // Deterministic confidence-descending emission order (shared with the other
    // host-recon collectors). No truncation.
    crate::util::recon::sort_by_confidence_desc(&mut out);
    out
}

/// What one walk of the issuance cursor retrieved and, when it stopped before
/// the end of the data, why.
struct Walk {
    entries: Vec<Issuance>,
    /// `None` iff the walk reached the end of the data — a short page (see
    /// [`PAGE_SIZE`]) or the API's own terminating empty array — so the answer
    /// is complete as far as Cert Spotter is concerned. `Some(cause)` names what
    /// cut it short, in the words [`ModuleResult::mark_truncated`] reports.
    cut: Option<String>,
}

fn issuances_url(base: &str, host: &str, after: Option<&str>) -> String {
    // `include_subdomains=true` widens the query from the apex to every
    // sub-name; the two `expand` params inline the dns_names + issuer so a
    // single request yields full detail (unexpanded, they are bare refs).
    let mut url = format!(
        "{base}?domain={}&include_subdomains=true&expand=dns_names&expand=issuer",
        urlencode(host)
    );
    if let Some(after) = after {
        url.push_str("&after=");
        url.push_str(&urlencode(after));
    }
    url
}

/// Follow Cert Spotter's `after=` cursor for `host`, up to `max_pages` pages,
/// requesting another page only while the walk is younger than
/// `next_page_cutoff`.
///
/// Before this, the module read the first page and reported it as the whole
/// answer: an apex with more than a page of live certificates lost every
/// subdomain past the first hundred issuances, and the coverage layer was told
/// the answer was complete.
///
/// - A **short page** (fewer than [`PAGE_SIZE`]) or an empty one ends the walk
///   as complete.
/// - A **full page** is followed, from its last issuance's `id`.
/// - Reaching `max_pages`, running out of time, or a full page whose last
///   issuance carries no `id` ends it **incomplete** — `cut` names which.
/// - A failed **first** request is the module's error, exactly as before: with
///   nothing retrieved, returning `Ok(empty)` would be a clean negative
///   fabricated from an outage. A failed **later** request keeps every page
///   already retrieved and reports the walk incomplete — the evidence is real,
///   and discarding it because a different page failed would be the partial
///   outage `ModuleResult::or_hard_failure` exists to prevent.
async fn walk_issuances(
    client: &reqwest::Client,
    base: &str,
    host: &str,
    max_pages: usize,
    next_page_cutoff: std::time::Duration,
) -> Result<Walk> {
    let started = std::time::Instant::now();
    let mut entries: Vec<Issuance> = Vec::new();
    let mut after: Option<String> = None;
    for page in 1..=max_pages {
        if page > 1 && started.elapsed() >= next_page_cutoff {
            return Ok(Walk {
                entries,
                cut: Some(format!(
                    "the {}s time budget for following Cert Spotter's `after=` cursor, before page {page}",
                    next_page_cutoff.as_secs()
                )),
            });
        }
        let url = issuances_url(base, host, after.as_deref());
        let batch: Vec<Issuance> = match crate::util::http::fetch_json(client, SRC, &url).await {
            Ok(batch) => batch,
            Err(e) if entries.is_empty() => return Err(e),
            Err(e) => {
                return Ok(Walk {
                    entries,
                    cut: Some(format!(
                        "a failed request for page {page} of Cert Spotter's `after=` cursor ({e})"
                    )),
                });
            }
        };
        let full = batch.len() >= PAGE_SIZE;
        let next = batch
            .last()
            .and_then(|last| last.id.clone())
            .filter(|id| !id.trim().is_empty());
        entries.extend(batch);
        if !full {
            return Ok(Walk { entries, cut: None });
        }
        let Some(next) = next else {
            return Ok(Walk {
                entries,
                cut: Some(format!(
                    "page {page} of Cert Spotter's `after=` cursor, a full page whose last issuance carried no `id` to continue from"
                )),
            });
        };
        after = Some(next);
    }
    Ok(Walk {
        entries,
        cut: Some(format!(
            "the cap of {max_pages} pages of Cert Spotter's `after=` cursor"
        )),
    })
}

/// The module's result for one walk: the entities of every page retrieved,
/// declared incomplete when the walk was cut short. **Pure** — this is the
/// seam between the walk's `cut` and the coverage layer, kept out of
/// `process()` so it is locked without a network.
fn walk_result(walk: Walk, host: &str, scan_id: &str) -> ModuleResult {
    let mut result = ModuleResult::new();
    result.entities = build_entities(&walk.entries, host, scan_id);
    if let Some(cause) = walk.cut {
        result.mark_truncated(result.entities.len(), None, &cause);
    }
    result
}

pub struct CertSpotter;

#[async_trait]
impl Module for CertSpotter {
    fn name(&self) -> &'static str {
        "certspotter"
    }

    fn description(&self) -> &'static str {
        "Certificate Transparency issuance search via Cert Spotter (free, no key)"
    }

    fn priority(&self) -> u8 {
        // One below `crtsh` (29): the two CT sources run back-to-back, and the
        // engine's per-target dedup means whichever surfaces a subdomain first
        // wins — order is immaterial to the union, but a stable priority keeps
        // dispatch deterministic.
        28
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain | TargetKind::Url)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::DnsRecon
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Search Open Technical Databases: Digital Certificates (T1596.003).
        &["T1596.003"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Domain, EntityKind::Organisation];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        // The walk may take several requests, and the server itself allows a
        // query 10 s before answering `504 {"code":"timeout",…}` — which the
        // previous 10 s budget killed before it could arrive, so a too-big
        // apex surfaced as an anonymous engine timeout instead of the server's
        // own explanation. No page starts after NEXT_PAGE_CUTOFF (10 s), so
        // one started just inside it still has the server's full 10 s plus
        // transfer before this fires, and the pages already retrieved survive.
        25_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let Some(host) = crate::util::recon::host_key(target.kind, &target.value) else {
            return Ok(ModuleResult::new());
        };

        // Shared `fetch_json` per page: Cert Spotter answers 200 with a JSON
        // array, matching fetch_json's error-on-non-2xx contract, and inherits
        // the curl/OpenSSL fallback + circuit breaker every keyless source uses
        // on Termux/DC IPs.
        let walk =
            walk_issuances(&ctx.http, ISSUANCES_URL, &host, MAX_PAGES, NEXT_PAGE_CUTOFF).await?;

        Ok(walk_result(walk, &host, &ctx.scan_id))
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
