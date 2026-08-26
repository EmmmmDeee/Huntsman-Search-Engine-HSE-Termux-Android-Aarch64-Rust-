//! Subdomain takeover detection — check if CNAME targets point to
//! unclaimed cloud services (S3, Azure, Heroku, GitHub Pages, etc.).
//!
//! When a subdomain has a CNAME pointing to a cloud provider but the
//! underlying resource is unclaimed, an attacker can register it and
//! serve content on the victim's subdomain. This module checks DNS
//! CNAME records against known vulnerable fingerprints.
//!
//! No API key required. Uses DNS resolution + HTTP fingerprint check.
//!
//! # A failed probe is not a finding
//!
//! This module *accuses a domain of being hijackable*, so it is the one place
//! in the engine where the direction of a wrong answer matters most — a false
//! positive here sends an operator to a customer with a vulnerability report
//! that is not true. Every network step below therefore distinguishes three
//! outcomes, never two:
//!
//! * **claimed** — the resource answered and is in use. Not vulnerable.
//! * **unclaimed** — the resource authoritatively does not exist (`NXDOMAIN`),
//!   or the provider served its own "nothing is deployed here" marker. This,
//!   and only this, supports a `vulnerable` finding.
//! * **inconclusive** — `SERVFAIL`, `REFUSED`, a timeout, no egress, a TLS
//!   error, a truncated body. Nothing was established, so nothing is reported
//!   either way; the module returns an error rather than a clean empty result.
//!
//! Collapsing the third case into either of the first two is the defect this
//! module was built to avoid: `lookup_ip(..).is_err()` treated *any* resolver
//! failure as proof of takeover, so on a host with no DNS egress every
//! `NXDOMAIN`-proven provider in the table reported `vulnerable` at
//! [`confidence::VERY_HIGH_PLUS`]. Mirrors the `dns_axfr` / `dns_intel`
//! fail-closed idiom.

use async_trait::async_trait;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "subdomain_takeover";

pub struct SubdomainTakeover;

/// How much a fingerprint's HTTP body marker discriminates "the provider has
/// nothing deployed here" from ordinary page text.
///
/// The distinction exists because a marker match is a *substring* search over
/// up to 256 KiB of body, so a marker's discriminating power — not merely its
/// presence — decides what the match is worth.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Marker {
    /// Names the provider's own unclaimed-resource page and appears
    /// essentially nowhere else: `NoSuchBucket`, `BlobNotFound`,
    /// `There isn't a GitHub Pages site here`. A match is strong evidence on
    /// its own and reports a confirmed `vulnerable` domain, as before.
    Distinctive,
    /// Generic English or a bare status number — `404`, `Not Found`,
    /// `not found`, `Bad request` — that a *legitimately owned* site can
    /// contain anywhere in its body: its own styled error page, an inlined JS
    /// bundle, a CSS class name, a support phone number. Matching `"404"`
    /// against 256 KiB of a working Vercel deployment is not evidence that the
    /// deployment is claimable.
    ///
    /// A generic match is still reported — suppressing it would trade a false
    /// positive for a false negative — but as an **unconfirmed candidate**: no
    /// `vulnerable` tag (so it does not feed the correlator's exposure rules
    /// and manufacture further findings from a substring), and a confidence
    /// that says what it is.
    Generic,
}

/// One takeover fingerprint: the CNAME substring that points at a cloud
/// provider, the human-readable service name, and the proof method — an HTTP
/// body marker plus how much that marker discriminates, or `None` to prove the
/// resource unclaimed via `NXDOMAIN` on the CNAME target instead.
type Fingerprint = (&'static str, &'static str, Option<(&'static str, Marker)>);

/// What a network probe established about one candidate resource.
///
/// Three-valued on purpose: see the module docs. `Inconclusive` is not a
/// failure to be swallowed — it is the answer, and it must reach the operator
/// rather than be rounded to whichever of the other two is nearer to hand.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Claim {
    /// The resource authoritatively does not exist, or the provider served its
    /// own unclaimed-resource marker. Supports a finding.
    Unclaimed(Proof),
    /// The resource answered and is in use. Not vulnerable, and that is a real
    /// negative the operator can rely on.
    Claimed,
    /// Nothing was established — `SERVFAIL`, `REFUSED`, timeout, no egress,
    /// TLS failure, unreadable body. Reported, never counted either way.
    Inconclusive,
}

/// How an [`Claim::Unclaimed`] verdict was reached, carried into the finding so
/// the evidence states its own provenance instead of asserting a bare verdict.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Proof {
    /// The CNAME target itself resolves to `NXDOMAIN`: the cloud resource is
    /// gone and the name is registrable. The strongest signal available here.
    NxDomain,
    /// The provider served a [`Marker::Distinctive`] unclaimed-resource page.
    DistinctiveMarker,
    /// A [`Marker::Generic`] substring matched. A candidate, not a proof.
    GenericMarker,
}

impl Proof {
    /// Confidence for a finding established this way.
    ///
    /// `NXDOMAIN` and a distinctive provider marker keep the module's original
    /// [`confidence::VERY_HIGH_PLUS`] — that behaviour was correct and is
    /// unchanged. A generic substring drops to [`confidence::LOW_MEDIUM`],
    /// which is what "this page contained the text `404` somewhere" is worth.
    fn confidence(self) -> f64 {
        match self {
            Self::NxDomain | Self::DistinctiveMarker => confidence::VERY_HIGH_PLUS,
            Self::GenericMarker => confidence::LOW_MEDIUM,
        }
    }

    /// Whether a finding established this way may claim the domain is
    /// `vulnerable` — the tag the correlator's exposure rules key on.
    fn is_confirmed(self) -> bool {
        matches!(self, Self::NxDomain | Self::DistinctiveMarker)
    }

    /// Human-readable provenance for the evidence line.
    fn describe(self) -> &'static str {
        match self {
            Self::NxDomain => "CNAME target does not resolve (NXDOMAIN) — the resource is gone",
            Self::DistinctiveMarker => "provider served its unclaimed-resource page",
            Self::GenericMarker => {
                "response body contained a generic not-found marker — unconfirmed"
            }
        }
    }
}

/// The fingerprints whose CNAME pattern is a substring of `cname_target`, in
/// table order. **Pure** — the pattern-matching half of detection, split out so
/// the "which providers does this CNAME implicate" logic is testable without
/// DNS or HTTP. The caller still runs each candidate's (network) claim check.
fn matching_fingerprints(cname_target: &str) -> impl Iterator<Item = &'static Fingerprint> {
    TAKEOVER_FINGERPRINTS
        .iter()
        .filter(move |(pattern, _, _)| cname_target.contains(pattern))
}

/// Classify a fetched body against one fingerprint. **Pure**, so the
/// marker-strength policy is unit-testable without a network.
///
/// A miss is [`Claim::Claimed`]: the provider answered and did not say the
/// resource is unclaimed. That is a real negative — unlike a transport failure,
/// which never reaches this function.
fn classify_body(body: &str, marker: &str, strength: Marker) -> Claim {
    if !body.contains(marker) {
        return Claim::Claimed;
    }
    Claim::Unclaimed(match strength {
        Marker::Distinctive => Proof::DistinctiveMarker,
        Marker::Generic => Proof::GenericMarker,
    })
}

/// Build the subdomain-takeover entity once a dangling CNAME has been confirmed
/// claimable. **Pure** (no network), so the CNAME→tag→evidence mapping is
/// unit-testable directly.
///
/// Emits a single `Domain` entity tagged `subdomain-takeover` +
/// `takeover:<service>`, carrying the CNAME target, service and the `proof` that
/// established it. [`Proof::is_confirmed`] decides whether it also carries
/// `vulnerable` and what confidence it gets — an unconfirmed candidate is
/// reported without claiming a vulnerability was proven. A blank `service` adds
/// no `takeover:` tag and no `service` attr; a blank `cname_target` adds no
/// `cname_target` attr.
fn build_entities(
    domain: &str,
    cname_target: &str,
    service: &str,
    proof: Proof,
    scan_id: &str,
) -> Vec<Entity> {
    let mut e = Entity::new(EntityKind::Domain, domain, proof.confidence(), scan_id);
    if proof.is_confirmed() {
        e.tag(crate::core::tags::VULNERABLE);
    } else {
        e.tag("takeover-candidate");
        e.tag("unconfirmed");
    }
    e.tag("subdomain-takeover");
    if !service.is_empty() {
        e.tag(format!("takeover:{service}"));
    }
    let claim = if proof.is_confirmed() {
        "may be claimable"
    } else {
        "may be claimable — UNCONFIRMED"
    };
    let mut ev = Evidence::new(
        SRC,
        format!(
            "CNAME {domain} points to {cname_target} — {service} {claim} ({})",
            proof.describe()
        ),
    )
    .with_attr("proof", format!("{proof:?}"))
    .with_attr("confirmed", proof.is_confirmed().to_string());
    if !cname_target.is_empty() {
        ev = ev.with_attr("cname_target", cname_target);
    }
    if !service.is_empty() {
        ev = ev.with_attr("service", service);
    }
    e.add_evidence(ev);
    vec![e]
}

#[async_trait]
impl Module for SubdomainTakeover {
    fn name(&self) -> &'static str {
        SRC
    }
    fn description(&self) -> &'static str {
        "Subdomain-takeover recon — fingerprints dangling CNAMEs to unmask hijackable subdomains"
    }
    fn priority(&self) -> u8 {
        40
    }
    fn max_timeout_ms(&self) -> u64 {
        8_000
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::DnsRecon
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // This module actively resolves a subdomain's CNAME and HTTP-probes the
        // target to prove a cloud resource is unclaimed/claimable — an exploitable
        // dangling-DNS misconfiguration it reports as a `vulnerable` Domain. That
        // is ATT&CK Active Scanning: Vulnerability Scanning (T1595.002) — scanning
        // a target for an exploitable condition — NOT the passive Domain
        // Properties (T1590.001) the DnsRecon category default would inherit
        // (which merely gathers domain metadata). Mirrors `portscan`, the other
        // active scanner that overrides its passive category default.
        &["T1595.002"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Domain];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();
        let domain = target.value.clone();

        if domain.is_empty() || !domain.contains('.') {
            return Ok(result);
        }

        let resolver = crate::util::dns::shared_resolver();
        // Resolve the CNAME chain and take the first CNAME answer, normalised to
        // a trailing-dot-free lower-case host.
        //
        // The error split is the `dns_axfr` idiom, and it matters for the same
        // reason: this is an EXPOSURE check, so `Ok(empty)` reads downstream as
        // "no takeover exposure on this domain". Emitting that for a domain whose
        // CNAME was never actually resolved reports a clean security result
        // produced by a resolver outage. `.ok()` did exactly that.
        let lookup = match resolver
            .lookup(&domain, hickory_resolver::proto::rr::RecordType::CNAME)
            .await
        {
            Ok(lookup) => lookup,
            // The zone authoritatively answered "no CNAME here" — NXDOMAIN, or
            // NOERROR with no answers. There is genuinely nothing to fingerprint,
            // so an empty result is the true answer. `is_no_records_found()` is
            // exactly this and nothing more: hickory maps SERVFAIL/REFUSED/FORMERR
            // to `ResponseCode(..)`, never to `NoRecordsFound`.
            Err(e) if e.is_no_records_found() => return Ok(result),
            // SERVFAIL, REFUSED, timeout, no route. Nothing was established about
            // this domain, so the check was not performed. Fail closed.
            Err(e) => {
                return Err(Error::module(
                    SRC,
                    format!(
                        "CNAME lookup for {domain} failed, so no takeover check was performed: {e}"
                    ),
                ));
            }
        };

        let cname = lookup.answers().iter().find_map(|record| {
            if let hickory_resolver::proto::rr::RData::CNAME(ref c) = record.data {
                Some(c.0.to_ascii().trim_end_matches('.').to_lowercase())
            } else {
                None
            }
        });

        let Some(cname_target) = cname else {
            return Ok(result);
        };

        // Track the probes that established nothing so a run in which EVERY
        // candidate was inconclusive cannot be returned as "no takeover
        // exposure". One inconclusive probe among several that answered is
        // recorded but does not sink the result — the answers are still real.
        let mut inconclusive: Vec<&'static str> = Vec::new();
        let mut answered = 0usize;

        for &(_, service, fingerprint) in matching_fingerprints(&cname_target) {
            let claim = match fingerprint {
                Some((marker, strength)) => {
                    check_http_fingerprint(&ctx.http, &domain, marker, strength).await
                }
                None => check_unclaimed(&cname_target).await,
            };

            match claim {
                Claim::Unclaimed(proof) => {
                    answered += 1;
                    result.extend(build_entities(
                        &domain,
                        &cname_target,
                        service,
                        proof,
                        &ctx.scan_id,
                    ));
                    break;
                }
                Claim::Claimed => answered += 1,
                Claim::Inconclusive => inconclusive.push(service),
            }
        }

        // Nothing answered and something was tried: the module reached no
        // conclusion at all. Returning `Ok(empty)` here would be a clean
        // "not vulnerable" verdict that no probe supports.
        if answered == 0 && !inconclusive.is_empty() {
            return Err(Error::module(
                SRC,
                format!(
                    "no takeover probe for {domain} (CNAME {cname_target}) reached a conclusion — \
                     all {} candidate service check(s) were blocked or unreachable ({}). \
                     Reporting this as 'no takeover exposure' would be a security verdict \
                     nothing established.",
                    inconclusive.len(),
                    inconclusive.join(", ")
                ),
            ));
        }

        Ok(result)
    }
}

/// Prove a CNAME target unclaimed by resolving it: only `NXDOMAIN` — the name
/// does not exist at all — means the cloud resource is gone and registrable.
///
/// `is_err()` was the original test, and it is true for `SERVFAIL`, `REFUSED`,
/// a timeout and a host with no DNS egress. On such a host every `NXDOMAIN`-
/// proven provider in the table (Azure Cloud, Elastic Beanstalk, Fly.io,
/// Cloudflare Pages) reported the domain `vulnerable` at
/// [`confidence::VERY_HIGH_PLUS`] — a fabricated vulnerability report produced
/// by a broken resolver.
///
/// `NOERROR` with no address records is deliberately **not** unclaimed either:
/// the name exists in DNS, so the provider still knows about it.
async fn check_unclaimed(cname_target: &str) -> Claim {
    let resolver = crate::util::dns::shared_resolver();
    match resolver.lookup_ip(cname_target).await {
        Ok(_) => Claim::Claimed,
        Err(e) if e.is_nx_domain() => Claim::Unclaimed(Proof::NxDomain),
        Err(e) if e.is_no_records_found() => Claim::Claimed,
        Err(_) => Claim::Inconclusive,
    }
}

/// Probe the subdomain over HTTP and classify the body against `marker`.
///
/// A timeout, transport error or unreadable body is [`Claim::Inconclusive`],
/// not "not vulnerable": the previous `_ => false` reported a clean negative for
/// a probe that never completed, which for an exposure check is the same defect
/// as the DNS path above pointing the other way.
async fn check_http_fingerprint(
    http: &reqwest::Client,
    domain: &str,
    marker: &str,
    strength: Marker,
) -> Claim {
    let url = format!("http://{domain}");
    match tokio::time::timeout(std::time::Duration::from_secs(5), http.get(&url).send()).await {
        Ok(Ok(resp)) => match crate::util::http::read_body_capped(resp, 256 * 1024).await {
            Some(body) => classify_body(&body, marker, strength),
            None => Claim::Inconclusive,
        },
        _ => Claim::Inconclusive,
    }
}

const TAKEOVER_FINGERPRINTS: &[Fingerprint] = &[
    // (CNAME pattern, service name, Some((HTTP body marker, how distinctive)) or
    //  None to prove via NXDOMAIN on the CNAME target)
    (
        "s3.amazonaws.com",
        "AWS S3",
        Some(("NoSuchBucket", Marker::Distinctive)),
    ),
    (
        "s3-website",
        "AWS S3 Website",
        Some(("NoSuchBucket", Marker::Distinctive)),
    ),
    (
        ".herokuapp.com",
        "Heroku",
        Some(("no-such-app", Marker::Distinctive)),
    ),
    (
        ".herokudns.com",
        "Heroku DNS",
        Some(("no-such-app", Marker::Distinctive)),
    ),
    (
        "github.io",
        "GitHub Pages",
        Some(("There isn't a GitHub Pages site here", Marker::Distinctive)),
    ),
    (
        ".azurewebsites.net",
        "Azure App Service",
        Some(("404 Web Site not found", Marker::Distinctive)),
    ),
    (".cloudapp.net", "Azure Cloud", None),
    (
        ".trafficmanager.net",
        "Azure Traffic Manager",
        Some(("404 Web Site not found", Marker::Distinctive)),
    ),
    (
        ".blob.core.windows.net",
        "Azure Blob",
        Some(("BlobNotFound", Marker::Distinctive)),
    ),
    // "Bad request" is CloudFront's response to a great many misconfigurations
    // that are not takeovers (a wrong Host header on a live distribution, most
    // commonly) — and this module always probes plain `http://domain`.
    (
        ".cloudfront.net",
        "AWS CloudFront",
        Some(("Bad request", Marker::Generic)),
    ),
    (".elasticbeanstalk.com", "AWS Elastic Beanstalk", None),
    (".ghost.io", "Ghost", Some(("404 error", Marker::Generic))),
    (
        ".myshopify.com",
        "Shopify",
        Some((
            "Sorry, this shop is currently unavailable",
            Marker::Distinctive,
        )),
    ),
    (
        ".surge.sh",
        "Surge.sh",
        Some(("project not found", Marker::Generic)),
    ),
    (
        ".bitbucket.io",
        "Bitbucket",
        Some(("Repository not found", Marker::Generic)),
    ),
    (
        ".netlify.app",
        "Netlify",
        Some(("Not Found", Marker::Generic)),
    ),
    (
        ".netlify.com",
        "Netlify",
        Some(("Not Found", Marker::Generic)),
    ),
    (
        ".pantheonsite.io",
        "Pantheon",
        Some(("404 error", Marker::Generic)),
    ),
    (
        ".wordpress.com",
        "WordPress",
        Some(("Do you want to register", Marker::Distinctive)),
    ),
    (
        ".tumblr.com",
        "Tumblr",
        Some(("There's nothing here", Marker::Generic)),
    ),
    (".fly.dev", "Fly.io", None),
    // A bare "404" matched anywhere in 256 KiB of body: a live deployment's own
    // styled error page, an inlined JS bundle, a CSS class, a support number.
    // The weakest marker in the table by a wide margin.
    (".vercel.app", "Vercel", Some(("404", Marker::Generic))),
    (
        ".render.com",
        "Render",
        Some(("not found", Marker::Generic)),
    ),
    (".pages.dev", "Cloudflare Pages", None),
];

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
