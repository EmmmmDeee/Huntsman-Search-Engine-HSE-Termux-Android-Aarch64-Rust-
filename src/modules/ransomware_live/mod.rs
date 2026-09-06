//! Ransomware.live victim lookup — free, keyless ransomware/extortion exposure.
//!
//! Endpoint: `GET https://api.ransomware.live/v2/searchvictims/<keyword>`. The v2
//! API is public and unauthenticated (confirmed against the provider's own
//! `/api` page: "Free — No authentication"). It full-text-searches the aggregated
//! ransomware-leak-site victim corpus and returns each matching victim with the
//! claiming group, the attack/discovery dates, country, sector, and a reference
//! URL.
//!
//! Contract (verified live against a real response, 2026-09) — an array of:
//!   `{victim, group, domain, country, activity, attackdate, discovered,
//!     claim_url, url, description}` (all string-ish; a miss is HTTP 404).
//!
//! Capability: given a `Domain` or `Organisation` seed, this answers "is this
//! subject a known ransomware/extortion victim, claimed by which group, when?" —
//! a net-new exposure signal no existing HSE module covers, and pure DISCOVERY
//! (it never fetches a leak site, only the public victim index).
//!
//! Precision over recall: the upstream search is full-text, so a bare keyword
//! can match unrelated victims via a description mention. This module keeps ONLY
//! victims whose own `domain` matches a `Domain` seed, or whose `victim` name
//! matches an `Organisation` seed — never emitting an incidental description hit
//! as if it were the subject (RULE.md: no fabricated or over-broad findings).

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::domains::is_or_subdomain_of;
use crate::util::http::{fetch_json_or_404, urlencode};

/// Stable evidence-source string. `pub(crate)` so a test can pin it and no
/// sibling module can silently claim the same corpus.
pub(crate) const SRC: &str = "ransomware_live";

/// One victim record from the v2 `searchvictims` array. Every field is optional
/// so a schema addition or a partially-populated record never fails the whole
/// parse into a false miss.
#[derive(Deserialize, Default)]
#[serde(default)]
struct Victim {
    victim: Option<String>,
    group: Option<String>,
    domain: Option<String>,
    country: Option<String>,
    activity: Option<String>,
    attackdate: Option<String>,
    discovered: Option<String>,
    claim_url: Option<String>,
    /// Ransomware.live's own canonical reference page for this victim.
    url: Option<String>,
}

/// Ransomware.live victim-index module (domain/org → ransomware/extortion
/// victim records, keyless).
pub struct RansomwareLive;

#[async_trait]
impl Module for RansomwareLive {
    fn name(&self) -> &'static str {
        SRC
    }

    fn description(&self) -> &'static str {
        "Ransomware.live victim index — keyless check of whether a domain or org is a known ransomware/extortion victim"
    }

    fn priority(&self) -> u8 {
        120
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain | TargetKind::Organisation)
    }

    fn category(&self) -> ModuleCategory {
        // Free-or-bought threat-intel vendor data about victim organisations —
        // the category's own definition. Its default ATT&CK mapping (T1597.001)
        // is correct; no override needed.
        ModuleCategory::Threat
    }

    fn max_timeout_ms(&self) -> u64 {
        12_000
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Organisation,
            EntityKind::Domain,
            EntityKind::Url,
        ];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let keyword = target.value.trim();
        if keyword.is_empty() {
            return Ok(ModuleResult::new());
        }
        let url = format!(
            "https://api.ransomware.live/v2/searchvictims/{}",
            urlencode(keyword)
        );
        // 404 is the upstream's clean "no such victim" signal → empty; any other
        // non-2xx surfaces as a real ModuleError (fail-closed).
        let Some(victims): Option<Vec<Victim>> = fetch_json_or_404(&ctx.http, SRC, &url).await?
        else {
            return Ok(ModuleResult::new());
        };
        Ok(build_result(&victims, target, &ctx.scan_id))
    }
}

/// How strongly a victim record matches the seed — drives both the retain
/// decision and the emitted confidence.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Match {
    /// The victim's own `domain` equals (or is a sub/parent-domain of) a
    /// `Domain` seed — an authoritative, unambiguous hit.
    Domain,
    /// The victim `name` matches an `Organisation` seed — real but fuzzier
    /// (organisation names are not unique keys).
    Org,
}

/// Decide whether `victim` genuinely IS the seed subject (not an incidental
/// description mention), and how strongly.
fn classify(victim: &Victim, target: &Target, needle: &str) -> Option<Match> {
    match target.kind {
        TargetKind::Domain => {
            let d = victim.domain.as_deref()?.trim().to_ascii_lowercase();
            // Label-safe equality-or-sub/parent-domain via the single-sourced
            // `util::domains` authority (no `format!` allocation, and it rejects
            // the `notexample.com`-matches-`example.com` bug a bare `ends_with`
            // would admit). Checked both directions so a victim `sub.acme.com`
            // matches an `acme.com` seed and vice versa.
            (is_or_subdomain_of(&d, needle) || is_or_subdomain_of(needle, &d))
                .then_some(Match::Domain)
        }
        TargetKind::Organisation => {
            let name = victim.victim.as_deref()?.trim().to_ascii_lowercase();
            if name.is_empty() {
                return None;
            }
            (name == needle || name.contains(needle) || needle.contains(&name))
                .then_some(Match::Org)
        }
        _ => None,
    }
}

/// Build entities from the matching victims. Pure of I/O so it is unit-tested
/// against fixtures; `process` stays a thin network adapter.
fn build_result(victims: &[Victim], target: &Target, scan_id: &str) -> ModuleResult {
    let mut result = ModuleResult::new();

    // Loop-invariant: the lowercased seed needle is identical for every victim,
    // so derive it once (was re-computed per victim inside `classify`).
    let needle = target.value.trim().to_ascii_lowercase();
    if needle.is_empty() {
        return result;
    }

    for v in victims {
        let Some(kind) = classify(v, target, &needle) else {
            continue;
        };
        let conf = match kind {
            Match::Domain => confidence::HIGH_PLUSPLUS,
            Match::Org => confidence::HIGH,
        };

        // Provenance shared by every entity this victim mints.
        let group = v.group.as_deref().map(str::trim).filter(|g| !g.is_empty());
        let ev = Evidence::new(SRC, "Ransomware.live victim index").with_optional_attrs([
            ("group", group),
            ("attackdate", v.attackdate.as_deref()),
            ("discovered", v.discovered.as_deref()),
            ("country", v.country.as_deref()),
            ("sector", v.activity.as_deref()),
            ("claim_url", v.claim_url.as_deref()),
            ("reference", v.url.as_deref()),
        ]);

        let group_tag = group.map(|g| format!("group:{}", g.to_lowercase()));
        // `Option<&str>::as_slice` yields a 0-or-1-element `&[&str]` with no
        // allocation — the per-record `group:` tag (if any) as extra tags.
        let group_slice = group_tag.as_deref();
        let group_extra: &[&str] = group_slice.as_slice();

        // The victim organisation — a genuine Organisation pivot when the seed
        // was a Domain, or a reinforcement when it was the Organisation itself.
        if let Some(name) = v.victim.as_deref().map(str::trim).filter(|n| n.len() >= 2) {
            let e = Entity::new(EntityKind::Organisation, name, conf, scan_id);
            result.push_with_tags(e, &ev, &[SRC, "ransomware-victim"], group_extra);
        }

        // The victim's domain — a new Domain pivot when the seed was an
        // Organisation, and a useful reinforcement when the seed was that
        // Domain itself: emitting it re-stamps the domain with the
        // `ransomware-victim` tag and the claiming group, so it is emitted
        // whenever the record carries one (it merges with a Domain seed).
        if let Some(dom) = v
            .domain
            .as_deref()
            .map(str::trim)
            .filter(|d| d.contains('.'))
        {
            let e = Entity::new(EntityKind::Domain, dom, conf, scan_id);
            result.push_with_tags(e, &ev, &[SRC, "ransomware-victim"], group_extra);
        }

        // The reference page — a durable lead for the analyst to corroborate.
        if let Some(reference) = v
            .url
            .as_deref()
            .map(str::trim)
            .filter(|u| u.starts_with("http"))
        {
            let e = Entity::new(EntityKind::Url, reference, confidence::HIGH_PLUS, scan_id);
            result.push_with_tags(
                e,
                &ev,
                &[SRC, "ransomware-victim", "reference"],
                group_extra,
            );
        }
    }

    result
}

#[cfg(test)]
mod tests;
