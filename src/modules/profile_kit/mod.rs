//! Shared entity-construction toolkit for developer-profile modules.
//!
//! The `code`-family profile modules (codeberg, gitea, sourceforge, cpan,
//! launchpad, bitbucket, gitlab, hexpm, codewars, dockerhub, huggingface, …)
//! all map a fetched account record onto the same handful of entity shapes:
//! a confirmed username, a profile URL, an optional real-name `Person`, an
//! optional personal website (`Url` + derived `Domain`), an optional
//! self-reported location (`Address`), and any emails embedded in a free-text
//! bio. Before this toolkit each module re-implemented the *structural* logic —
//! the multi-word-name gate, the `http(s)` URL filter, the website→domain host
//! exclusion, the location length guard, the bio email-extraction loop — with
//! subtly inconsistent variations (drifting exclusion lists, a missing
//! placeholder check here, an off-by-one `take` there).
//!
//! Centralising the **logic** here removes that duplication and the
//! inconsistency. Each module still owns its **calibration** (confidence values
//! and platform-specific tags / evidence are supplied by the caller), so the
//! toolkit changes *how* the shared shapes are built, never *what* a given
//! module is allowed to emit. The helpers return un-tagged entities; the caller
//! decorates them with platform tags and evidence before pushing.

#[cfg(test)]
mod tests;

use crate::core::entity::{Entity, EntityKind};

/// Well-known code-hosting / professional-network hosts that must never be
/// promoted to a first-class `Domain` from a profile's self-reported website:
/// they are the platform's own canonical host or a major peer, not the
/// subject's personal infrastructure. A handle's GitHub/LinkedIn link is an
/// account pointer already captured as a `Url`, so emitting its host as a
/// `Domain` would seed correlation on shared platform infrastructure rather
/// than on the subject. Centralised so every profile module excludes the *same*
/// set — previously each hard-coded a different, drifting subset.
pub(crate) const PLATFORM_HOSTS: &[&str] = &[
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "codeberg.org",
    "gitea.com",
    "sourceforge.net",
    "metacpan.org",
    "cpan.org",
    "launchpad.net",
    "hex.pm",
    "codewars.com",
    "hub.docker.com",
    "huggingface.co",
    "crates.io",
    "npmjs.com",
    "rubygems.org",
    "pypi.org",
    "hackage.haskell.org",
    "clojars.org",
    "packagist.org",
    "pub.dev",
    "linkedin.com",
    "twitter.com",
    "x.com",
];

/// Resolve a canonical profile URL: prefer the API-provided link when it is an
/// absolute `http(s)` URL (with any trailing slash trimmed); otherwise fall
/// back to a constructed URL. The "filter the supplied link, else construct
/// one" two-step appeared verbatim — with gratuitously different trailing-slash
/// handling — in every profile module.
pub(crate) fn profile_url(api_link: Option<&str>, fallback: impl FnOnce() -> String) -> String {
    api_link
        .map(str::trim)
        .map(|u| u.trim_end_matches('/'))
        .filter(|u| u.starts_with("http"))
        .map_or_else(fallback, str::to_string)
}

/// Build a `Person` from a display / full name **iff** it carries ≥2
/// whitespace-separated tokens (a single token is a handle, not a real name)
/// and is not a known placeholder (`"Anonymous"`, `"N/A"`, …). Returns `None`
/// otherwise. The caller adds platform tags and evidence.
pub(crate) fn person_from_name(name: &str, confidence: f64, scan_id: &str) -> Option<Entity> {
    let name = name.trim();
    if name.split_whitespace().count() < 2
        || crate::core::validation::is_placeholder_entity(&EntityKind::Person, name)
    {
        return None;
    }
    Some(Entity::new(EntityKind::Person, name, confidence, scan_id))
}

/// Build a `Url` entity for a self-reported personal website and, when the host
/// is a genuine third-party domain (carries a dot, is not a [`PLATFORM_HOSTS`]
/// entry, and is not a placeholder), a derived `Domain` entity. Returns an
/// empty vector when the website is not an absolute `http(s)` URL.
///
/// The returned entities are un-tagged: the caller tags the `Url` and `Domain`
/// (the `Domain` is conventionally also tagged `derived`) and attaches the
/// website evidence. Order is stable: index 0 is always the `Url`, index 1 (if
/// present) the `Domain`.
pub(crate) fn website_url_and_domain(
    site: &str,
    url_confidence: f64,
    domain_confidence: f64,
    scan_id: &str,
) -> Vec<Entity> {
    let site = site.trim();
    if !(site.starts_with("http://") || site.starts_with("https://")) {
        return Vec::new();
    }
    let mut out = vec![Entity::new(EntityKind::Url, site, url_confidence, scan_id)];
    if let Some(host) = crate::util::url_util::host_from_url(site)
        && host.contains('.')
        && !PLATFORM_HOSTS.contains(&host.as_str())
        && !crate::core::validation::is_placeholder_entity(&EntityKind::Domain, &host)
    {
        out.push(Entity::new(
            EntityKind::Domain,
            &host,
            domain_confidence,
            scan_id,
        ));
    }
    out
}

/// Build an `Address` from a self-reported location string when it is non-empty
/// and ≤100 characters (a longer value is a bio mis-mapped to the location
/// field, not a place). Returns `None` otherwise. The caller tags it
/// `self-asserted` and attaches evidence.
pub(crate) fn location_address(loc: &str, confidence: f64, scan_id: &str) -> Option<Entity> {
    let trimmed = loc.trim();
    if trimmed.is_empty() || trimmed.len() > 100 {
        return None;
    }
    Some(Entity::new(
        EntityKind::Address,
        trimmed,
        confidence,
        scan_id,
    ))
}

/// Attempt to geocode a self-reported location string to a `Coordinates`
/// entity using the city-centroid lookup. Returns `None` when the string is
/// unrecognised or the location guard rejects it. `coord_confidence` should
/// be slightly below the companion Address confidence (typically −0.10).
/// The caller tags and evidences the returned entity.
pub(crate) fn location_coordinates(
    loc: &str,
    coord_confidence: f64,
    scan_id: &str,
) -> Option<Entity> {
    let trimmed = loc.trim();
    if trimmed.is_empty() || trimmed.len() > 100 {
        return None;
    }
    let (lat, lon) = crate::util::city_coords::city_coords(trimmed)?;
    let coord_val = format!("{lat:.4},{lon:.4}");
    let mut c = Entity::new(
        EntityKind::Coordinates,
        &coord_val,
        coord_confidence,
        scan_id,
    );
    c.tag("addr-derived");
    c.tag("geoint");
    Some(c)
}

/// Extract EVERY `Email` entity mentioned in a free-text bio / description field,
/// in first-seen order (deduped by [`crate::util::extract::emails`]). A profile
/// bio is a bounded field, so there is no cap: a prior `.take(limit)` silently
/// dropped real contact-email pivots past the 3rd–5th on the handful of bios that
/// list several. The caller tags and evidences each returned entity.
pub(crate) fn bio_emails(bio: &str, confidence: f64, scan_id: &str) -> Vec<Entity> {
    crate::util::extract::emails(bio)
        .into_iter()
        .map(|email| Entity::new(EntityKind::Email, &email, confidence, scan_id))
        .collect()
}
